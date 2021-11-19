// Copyright (C) 2014-2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"bytes"
	"context"
	"fmt"
	"k8s.io/klog/v2"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	uuid "github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/internal/pkg/zebra"
	"github.com/osrg/gobgp/pkg/packet/bgp"
)

type tcpListener struct {
	l  *net.TCPListener
	ch chan struct{}
}

func (l *tcpListener) Close() error {
	if err := l.l.Close(); err != nil {
		return err
	}
	<-l.ch
	return nil
}

// avoid mapped IPv6 address
func newTCPListener(address string, port uint32, bindToDev string, ch chan *net.TCPConn) (*tcpListener, error) {
	proto := "tcp4"
	family := syscall.AF_INET
	if ip := net.ParseIP(address); ip == nil {
		return nil, fmt.Errorf("can't listen on %s", address)
	} else if ip.To4() == nil {
		proto = "tcp6"
		family = syscall.AF_INET6
	}
	addr := net.JoinHostPort(address, strconv.Itoa(int(port)))

	var lc net.ListenConfig
	lc.Control = func(network, address string, c syscall.RawConn) error {
		if bindToDev != "" {
			err := setBindToDevSockopt(c, bindToDev)
			if err != nil {
				log.WithFields(log.Fields{
					"Topic":     "Peer",
					"Key":       addr,
					"BindToDev": bindToDev,
				}).Warnf("failed to bind Listener to device (%s): %s", bindToDev, err)
				return err
			}
		}
		// Note: Set TTL=255 for incoming connection listener in order to accept
		// connection in case for the neighbor has TTL Security settings.
		err := setsockoptIpTtl(c, family, 255)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Warnf("cannot set TTL(=%d) for TCPListener: %s", 255, err)
		}
		return nil
	}

	l, err := lc.Listen(context.Background(), proto, addr)
	if err != nil {
		return nil, err
	}
	listener, ok := l.(*net.TCPListener)
	if !ok {
		err = fmt.Errorf("unexpected connection listener (not for TCP)")
		return nil, err
	}

	closeCh := make(chan struct{})
	go func() error {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				close(closeCh)
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Error": err,
				}).Warn("Failed to AcceptTCP")
				return err
			}
			ch <- conn
		}
	}()
	return &tcpListener{
		l:  listener,
		ch: closeCh,
	}, nil
}

type options struct {
	grpcAddress string
	grpcOption  []grpc.ServerOption
}

type ServerOption func(*options)

func GrpcListenAddress(addr string) ServerOption {
	return func(o *options) {
		o.grpcAddress = addr
	}
}

func GrpcOption(opt []grpc.ServerOption) ServerOption {
	return func(o *options) {
		o.grpcOption = opt
	}
}

type BgpServer struct {
	incomingCh chan *fsmMsg
	acceptCh   chan *net.TCPConn

	bgpConfig    config.Bgp
	mgmtCh       chan *mgmtOp
	policy       *table.RoutingPolicy
	listeners    []*tcpListener
	neighborMap  map[string]*peer
	peerGroupMap map[string]*peerGroup
	globalRib    *table.TableManager
	rsRib        *table.TableManager
	//roaManager   *roaManager
	shutdownWG *sync.WaitGroup
	watcherMap map[watchEventType][]*watcher
	//zclient      *zebraClient
	//bmpManager   *bmpClientManager
	roaTable *table.ROATable
	uuidMap  map[string]uuid.UUID
}

func NewBgpServer(opt ...ServerOption) *BgpServer {
	opts := options{}
	for _, o := range opt {
		o(&opts)
	}
	roaTable := table.NewROATable()
	s := &BgpServer{
		incomingCh: make(chan *fsmMsg, 1024),

		neighborMap:  make(map[string]*peer),
		peerGroupMap: make(map[string]*peerGroup),
		policy:       table.NewRoutingPolicy(),
		mgmtCh:       make(chan *mgmtOp, 1),
		watcherMap:   make(map[watchEventType][]*watcher),
		uuidMap:      make(map[string]uuid.UUID),
		roaTable:     roaTable,
	}
	if len(opts.grpcAddress) != 0 {
		grpc.EnableTracing = false
		apiServer := newAPIserver(s, grpc.NewServer(opts.grpcOption...), opts.grpcAddress)
		go func() {
			if err := apiServer.serve(); err != nil {
				log.Fatalf("failed to listen grpc port: %s", err)
			}
		}()
	}
	return s
}

func (s *BgpServer) Serve() {
	s.listeners = make([]*tcpListener, 0, 2)

	handlefsmMsg := func(msg *fsmMsg) {
		peer, found := s.neighborMap[msg.MsgSrc]
		if !found {
			log.WithFields(log.Fields{
				"Topic": "Peer",
			}).Warnf("Can't find the neighbor %s", msg.MsgSrc)
			return
		}
		s.handleFSMMessage(peer, msg)
	}

	for {
		select {
		case op := <-s.mgmtCh:
			s.handleMGMTOp(op)
		case conn := <-s.acceptCh:
			s.passConnToPeer(conn)
		case msg := <-s.incomingCh:
			handlefsmMsg(msg)
		}
	}
}

func (s *BgpServer) StartBgp(ctx context.Context, r *api.StartBgpRequest) error {
	if r == nil || r.Global == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		g := r.Global
		if net.ParseIP(g.RouterId) == nil {
			return fmt.Errorf("invalid router-id format: %s", g.RouterId)
		}

		c := newGlobalFromAPIStruct(g)
		if err := config.SetDefaultGlobalConfigValues(c); err != nil {
			return err
		}

		if c.Config.Port > 0 {
			acceptCh := make(chan *net.TCPConn, 4096)
			for _, addr := range c.Config.LocalAddressList {
				l, err := newTCPListener(addr, uint32(c.Config.Port), g.BindToDevice, acceptCh) // 127.0.0.1:1790
				if err != nil {
					return err
				}
				s.listeners = append(s.listeners, l)
			}
			s.acceptCh = acceptCh
		}

		rfs, _ := config.AfiSafis(c.AfiSafis).ToRfList()
		s.globalRib = table.NewTableManager(rfs)
		s.rsRib = table.NewTableManager(rfs)

		if err := s.policy.Initialize(); err != nil {
			return err
		}
		s.bgpConfig.Global = *c
		// update route selection options
		table.SelectionOptions = c.RouteSelectionOptions.Config
		table.UseMultiplePaths = c.UseMultiplePaths.Config
		return nil
	}, false)
}

func (s *BgpServer) StopBgp(ctx context.Context, r *api.StopBgpRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	s.mgmtOperation(func() error {
		names := make([]string, 0, len(s.neighborMap))
		for k := range s.neighborMap {
			names = append(names, k)
		}

		if len(names) != 0 {
			s.shutdownWG = new(sync.WaitGroup)
			s.shutdownWG.Add(1)
		}
		for _, name := range names {
			if err := s.deleteNeighbor(&config.Neighbor{Config: config.NeighborConfig{
				NeighborAddress: name}}, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED); err != nil {
				return err
			}
		}
		for _, l := range s.listeners {
			l.Close()
		}
		s.bgpConfig.Global = config.Global{}
		return nil
	}, false)

	if s.shutdownWG != nil {
		s.shutdownWG.Wait()
		s.shutdownWG = nil
	}
	return nil
}

func (s *BgpServer) GetBgp(ctx context.Context, r *api.GetBgpRequest) (*api.GetBgpResponse, error) {
	if r == nil {
		return nil, fmt.Errorf("nil request")
	}
	var rsp *api.GetBgpResponse
	s.mgmtOperation(func() error {
		g := s.bgpConfig.Global
		rsp = &api.GetBgpResponse{
			Global: &api.Global{
				As:               g.Config.As,
				RouterId:         g.Config.RouterId,
				ListenPort:       g.Config.Port,
				ListenAddresses:  g.Config.LocalAddressList,
				UseMultiplePaths: g.UseMultiplePaths.Config.Enabled,
			},
		}
		return nil
	}, false)
	return rsp, nil
}

func (s *BgpServer) handleFSMMessage(peer *peer, e *fsmMsg) {
	switch e.MsgType {
	case fsmMsgStateChange:
		nextState := e.MsgData.(bgp.FSMState)
		peer.fsm.lock.Lock()
		oldState := bgp.FSMState(peer.fsm.pConf.State.SessionState.ToInt())
		peer.fsm.pConf.State.SessionState = config.IntToSessionStateMap[int(nextState)]
		peer.fsm.lock.Unlock()

		peer.fsm.StateChange(nextState)

		peer.fsm.lock.RLock()
		nextStateIdle := peer.fsm.pConf.GracefulRestart.State.PeerRestarting && nextState == bgp.BGP_FSM_IDLE
		peer.fsm.lock.RUnlock()

		// PeerDown
		if oldState == bgp.BGP_FSM_ESTABLISHED {
			t := time.Now()
			peer.fsm.lock.Lock()
			if t.Sub(time.Unix(peer.fsm.pConf.Timers.State.Uptime, 0)) < flopThreshold {
				peer.fsm.pConf.State.Flops++
			}
			graceful := peer.fsm.reason.Type == fsmGracefulRestart
			peer.fsm.lock.Unlock()
			var drop []bgp.RouteFamily
			if graceful {
				peer.fsm.lock.Lock()
				peer.fsm.pConf.GracefulRestart.State.PeerRestarting = true
				for i := range peer.fsm.pConf.AfiSafis {
					peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = false
				}
				peer.fsm.lock.Unlock()
				var p []bgp.RouteFamily
				p, drop = peer.forwardingPreservedFamilies()
				s.propagateUpdate(peer, peer.StaleAll(p))
			} else {
				drop = peer.configuredRFlist()
			}
			peer.prefixLimitWarned = make(map[bgp.RouteFamily]bool)
			s.propagateUpdate(peer, peer.DropAll(drop))

			peer.fsm.lock.Lock()
			if peer.fsm.pConf.Config.PeerAs == 0 {
				peer.fsm.pConf.State.PeerAs = 0
				peer.fsm.peerInfo.AS = 0
			}
			peer.fsm.lock.Unlock()

			if !graceful && peer.isDynamicNeighbor() {
				s.deleteDynamicNeighbor(peer, oldState, e)
				return
			}

		} else if nextStateIdle {
			peer.fsm.lock.RLock()
			longLivedEnabled := peer.fsm.pConf.GracefulRestart.State.LongLivedEnabled
			peer.fsm.lock.RUnlock()
			if longLivedEnabled {
				llgr, no_llgr := peer.llgrFamilies()

				s.propagateUpdate(peer, peer.DropAll(no_llgr))

				// attach LLGR_STALE community to paths in peer's adj-rib-in
				// paths with NO_LLGR are deleted
				pathList := peer.markLLGRStale(llgr)

				// calculate again
				// wheh path with LLGR_STALE chosen as best,
				// peer which doesn't support LLGR will drop the path
				// if it is in adj-rib-out, do withdrawal
				s.propagateUpdate(peer, pathList)

				for _, f := range llgr {
					endCh := make(chan struct{})
					peer.llgrEndChs = append(peer.llgrEndChs, endCh)
					go func(family bgp.RouteFamily, endCh chan struct{}) {
						t := peer.llgrRestartTime(family)
						timer := time.NewTimer(time.Second * time.Duration(t))

						log.WithFields(log.Fields{
							"Topic":  "Peer",
							"Key":    peer.ID(),
							"Family": family,
						}).Infof("start LLGR restart timer (%d sec) for %s", t, family)

						select {
						case <-timer.C:
							s.mgmtOperation(func() error {
								log.WithFields(log.Fields{
									"Topic":  "Peer",
									"Key":    peer.ID(),
									"Family": family,
								}).Infof("LLGR restart timer (%d sec) for %s expired", t, family)
								s.propagateUpdate(peer, peer.DropAll([]bgp.RouteFamily{family}))

								// when all llgr restart timer expired, stop PeerRestarting
								if peer.llgrRestartTimerExpired(family) {
									peer.stopPeerRestarting()
								}
								return nil
							}, false)
						case <-endCh:
							log.WithFields(log.Fields{
								"Topic":  "Peer",
								"Key":    peer.ID(),
								"Family": family,
							}).Infof("stop LLGR restart timer (%d sec) for %s", t, family)
						}
					}(f, endCh)
				}
			} else {
				// RFC 4724 4.2
				// If the session does not get re-established within the "Restart Time"
				// that the peer advertised previously, the Receiving Speaker MUST
				// delete all the stale routes from the peer that it is retaining.
				peer.fsm.lock.Lock()
				peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
				peer.fsm.lock.Unlock()

				s.propagateUpdate(peer, peer.DropAll(peer.configuredRFlist()))

				if peer.isDynamicNeighbor() {
					s.deleteDynamicNeighbor(peer, oldState, e)
					return
				}
			}
		}

		if nextState == bgp.BGP_FSM_ESTABLISHED {
			// update for export policy
			laddr, _ := peer.fsm.LocalHostPort()
			// may include zone info
			peer.fsm.lock.Lock()
			peer.fsm.pConf.Transport.State.LocalAddress = laddr
			// exclude zone info
			ipaddr, _ := net.ResolveIPAddr("ip", laddr)
			peer.fsm.peerInfo.LocalAddress = ipaddr.IP
			neighborAddress := peer.fsm.pConf.State.NeighborAddress
			peer.fsm.lock.Unlock()
			deferralExpiredFunc := func(family bgp.RouteFamily) func() {
				return func() {
					s.mgmtOperation(func() error {
						s.softResetOut(neighborAddress, family, true)
						return nil
					}, false)
				}
			}
			peer.fsm.lock.RLock()
			notLocalRestarting := !peer.fsm.pConf.GracefulRestart.State.LocalRestarting
			peer.fsm.lock.RUnlock()
			if notLocalRestarting {
				// When graceful-restart cap (which means intention
				// of sending EOR) and route-target address family are negotiated,
				// send route-target NLRIs first, and wait to send others
				// till receiving EOR of route-target address family.
				// This prevents sending uninterested routes to peers.
				//
				// However, when the peer is graceful restarting, give up
				// waiting sending non-route-target NLRIs since the peer won't send
				// any routes (and EORs) before we send ours (or deferral-timer expires).
				var pathList []*table.Path
				peer.fsm.lock.RLock()
				_, y := peer.fsm.rfMap[bgp.RF_RTC_UC]
				c := peer.fsm.pConf.GetAfiSafi(bgp.RF_RTC_UC)
				notPeerRestarting := !peer.fsm.pConf.GracefulRestart.State.PeerRestarting
				peer.fsm.lock.RUnlock()
				if y && notPeerRestarting && c.RouteTargetMembership.Config.DeferralTime > 0 {
					pathList, _ = s.getBestFromLocal(peer, []bgp.RouteFamily{bgp.RF_RTC_UC})
					t := c.RouteTargetMembership.Config.DeferralTime
					for _, f := range peer.negotiatedRFList() {
						if f != bgp.RF_RTC_UC {
							time.AfterFunc(time.Second*time.Duration(t), deferralExpiredFunc(f))
						}
					}
				} else {
					pathList, _ = s.getBestFromLocal(peer, peer.negotiatedRFList())
				}

				if len(pathList) > 0 {
					sendfsmOutgoingMsg(peer, pathList, nil, false)
				}
			} else {
				// RFC 4724 4.1
				// Once the session between the Restarting Speaker and the Receiving
				// Speaker is re-established, ...snip... it MUST defer route
				// selection for an address family until it either (a) receives the
				// End-of-RIB marker from all its peers (excluding the ones with the
				// "Restart State" bit set in the received capability and excluding the
				// ones that do not advertise the graceful restart capability) or (b)
				// the Selection_Deferral_Timer referred to below has expired.
				allEnd := func() bool {
					for _, p := range s.neighborMap {
						if !p.recvedAllEOR() {
							return false
						}
					}
					return true
				}()
				if allEnd {
					for _, p := range s.neighborMap {
						p.fsm.lock.Lock()
						p.fsm.pConf.GracefulRestart.State.LocalRestarting = false
						p.fsm.lock.Unlock()
						if !p.isGracefulRestartEnabled() {
							continue
						}
						paths, _ := s.getBestFromLocal(p, p.configuredRFlist())
						if len(paths) > 0 {
							sendfsmOutgoingMsg(p, paths, nil, false)
						}
					}
					log.WithFields(log.Fields{
						"Topic": "Server",
					}).Info("sync finished")
				} else {
					peer.fsm.lock.RLock()
					deferral := peer.fsm.pConf.GracefulRestart.Config.DeferralTime
					peer.fsm.lock.RUnlock()
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   peer.ID(),
					}).Debugf("Now syncing, suppress sending updates. start deferral timer(%d)", deferral)
					time.AfterFunc(time.Second*time.Duration(deferral), deferralExpiredFunc(bgp.RouteFamily(0)))
				}
			}
		} else {
			peer.fsm.lock.Lock()
			peer.fsm.pConf.Timers.State.Downtime = time.Now().Unix()
			peer.fsm.lock.Unlock()
		}
		// clear counter
		peer.fsm.lock.RLock()
		adminStateDown := peer.fsm.adminState == adminStateDown
		peer.fsm.lock.RUnlock()
		if adminStateDown {
			peer.fsm.lock.Lock()
			peer.fsm.pConf.State = config.NeighborState{}
			peer.fsm.pConf.State.NeighborAddress = peer.fsm.pConf.Config.NeighborAddress
			peer.fsm.pConf.State.PeerAs = peer.fsm.pConf.Config.PeerAs
			peer.fsm.pConf.Timers.State = config.TimersState{}
			peer.fsm.lock.Unlock()
		}
		peer.startFSMHandler()
		s.broadcastPeerState(peer, oldState, e)
	case fsmMsgRouteRefresh:
		peer.fsm.lock.RLock()
		notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
		beforeUptime := e.timestamp.Unix() < peer.fsm.pConf.Timers.State.Uptime
		peer.fsm.lock.RUnlock()
		if notEstablished || beforeUptime {
			return
		}
		if paths := s.handleRouteRefresh(peer, e); len(paths) > 0 {
			sendfsmOutgoingMsg(peer, paths, nil, false)
			return
		}
	case fsmMsgBGPMessage:
		switch m := e.MsgData.(type) {
		case *bgp.MessageError:
			sendfsmOutgoingMsg(peer, nil, bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data), false)
			return
		case *bgp.BGPMessage:
			s.notifyRecvMessageWatcher(peer, e.timestamp, m)
			peer.fsm.lock.RLock()
			notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
			beforeUptime := e.timestamp.Unix() < peer.fsm.pConf.Timers.State.Uptime
			peer.fsm.lock.RUnlock()
			if notEstablished || beforeUptime {
				return
			}
			pathList, eor, notification := peer.handleUpdate(e)
			if notification != nil {
				sendfsmOutgoingMsg(peer, nil, notification, true)
				return
			}
			if m.Header.Type == bgp.BGP_MSG_UPDATE {
				s.notifyPrePolicyUpdateWatcher(peer, pathList, m, e.timestamp, e.payload)
			}

			if len(pathList) > 0 {
				s.propagateUpdate(peer, pathList)
			}

			peer.fsm.lock.RLock()
			peerAfiSafis := peer.fsm.pConf.AfiSafis
			peer.fsm.lock.RUnlock()
			if len(eor) > 0 {
				rtc := false
				for _, f := range eor {
					if f == bgp.RF_RTC_UC {
						rtc = true
					}
					for i, a := range peerAfiSafis {
						if a.State.Family == f {
							peer.fsm.lock.Lock()
							peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = true
							peer.fsm.lock.Unlock()
						}
					}
				}

				// RFC 4724 4.1
				// Once the session between the Restarting Speaker and the Receiving
				// Speaker is re-established, ...snip... it MUST defer route
				// selection for an address family until it either (a) receives the
				// End-of-RIB marker from all its peers (excluding the ones with the
				// "Restart State" bit set in the received capability and excluding the
				// ones that do not advertise the graceful restart capability) or ...snip...

				peer.fsm.lock.RLock()
				localRestarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
				peer.fsm.lock.RUnlock()
				if localRestarting {
					allEnd := func() bool {
						for _, p := range s.neighborMap {
							if !p.recvedAllEOR() {
								return false
							}
						}
						return true
					}()
					if allEnd {
						for _, p := range s.neighborMap {
							p.fsm.lock.Lock()
							p.fsm.pConf.GracefulRestart.State.LocalRestarting = false
							p.fsm.lock.Unlock()
							if !p.isGracefulRestartEnabled() {
								continue
							}
							paths, _ := s.getBestFromLocal(p, p.negotiatedRFList())
							if len(paths) > 0 {
								sendfsmOutgoingMsg(p, paths, nil, false)
							}
						}
						log.WithFields(log.Fields{
							"Topic": "Server",
						}).Info("sync finished")

					}

					// we don't delay non-route-target NLRIs when local-restarting
					rtc = false
				}
				peer.fsm.lock.RLock()
				peerRestarting := peer.fsm.pConf.GracefulRestart.State.PeerRestarting
				peer.fsm.lock.RUnlock()
				if peerRestarting {
					if peer.recvedAllEOR() {
						peer.stopPeerRestarting()
						pathList := peer.adjRibIn.DropStale(peer.configuredRFlist())
						peer.fsm.lock.RLock()
						log.WithFields(log.Fields{
							"Topic": "Peer",
							"Key":   peer.fsm.pConf.State.NeighborAddress,
						}).Debugf("withdraw %d stale routes", len(pathList))
						peer.fsm.lock.RUnlock()
						s.propagateUpdate(peer, pathList)
					}

					// we don't delay non-route-target NLRIs when peer is restarting
					rtc = false
				}

				// received EOR of route-target address family
				// outbound filter is now ready, let's flash non-route-target NLRIs
				peer.fsm.lock.RLock()
				c := peer.fsm.pConf.GetAfiSafi(bgp.RF_RTC_UC)
				peer.fsm.lock.RUnlock()
				if rtc && c != nil && c.RouteTargetMembership.Config.DeferralTime > 0 {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   peer.ID(),
					}).Debug("received route-target eor. flash non-route-target NLRIs")
					families := make([]bgp.RouteFamily, 0, len(peer.negotiatedRFList()))
					for _, f := range peer.negotiatedRFList() {
						if f != bgp.RF_RTC_UC {
							families = append(families, f)
						}
					}
					if paths, _ := s.getBestFromLocal(peer, families); len(paths) > 0 {
						sendfsmOutgoingMsg(peer, paths, nil, false)
					}
				}
			}
		default:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.fsm.pConf.State.NeighborAddress,
				"Data":  e.MsgData,
			}).Panic("unknown msg type")
		}
	}
}

func (s *BgpServer) listListeners(addr string) []*net.TCPListener {
	list := make([]*net.TCPListener, 0, len(s.listeners))
	rhs := net.ParseIP(addr).To4() != nil
	for _, l := range s.listeners {
		host, _, _ := net.SplitHostPort(l.l.Addr().String())
		lhs := net.ParseIP(host).To4() != nil
		if lhs == rhs {
			list = append(list, l.l)
		}
	}
	return list
}

func (s *BgpServer) active() error {
	if s.bgpConfig.Global.Config.As == 0 {
		return fmt.Errorf("bgp server hasn't started yet")
	}
	return nil
}

type mgmtOp struct {
	f           func() error
	errCh       chan error
	checkActive bool // check BGP global setting is configured before calling f()
}

func (s *BgpServer) handleMGMTOp(op *mgmtOp) {
	if op.checkActive {
		if err := s.active(); err != nil {
			op.errCh <- err
			return
		}
	}
	op.errCh <- op.f()
}

func (s *BgpServer) mgmtOperation(f func() error, checkActive bool) (err error) {
	ch := make(chan error)
	defer func() { err = <-ch }()
	s.mgmtCh <- &mgmtOp{
		f:           f,
		errCh:       ch,
		checkActive: checkActive,
	}
	return
}

func (s *BgpServer) passConnToPeer(conn *net.TCPConn) {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	ipaddr, _ := net.ResolveIPAddr("ip", host)
	remoteAddr := ipaddr.String()
	klog.Infof(fmt.Sprintf("[passConnToPeer]remoteAddr:%s", remoteAddr))
	peer, found := s.neighborMap[remoteAddr]
	if found {
		peer.fsm.lock.RLock()
		adminStateNotUp := peer.fsm.adminState != adminStateUp
		peer.fsm.lock.RUnlock()
		if adminStateNotUp {
			peer.fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic":       "Peer",
				"Remote Addr": remoteAddr,
				"Admin State": peer.fsm.adminState,
			}).Debug("New connection for non admin-state-up peer")
			peer.fsm.lock.RUnlock()
			conn.Close()
			return
		}
		peer.fsm.lock.RLock()
		localAddr := peer.fsm.pConf.Transport.Config.LocalAddress
		bindInterface := peer.fsm.pConf.Transport.Config.BindInterface
		peer.fsm.lock.RUnlock()
		localAddrValid := func(laddr string) bool {
			if laddr == "0.0.0.0" || laddr == "::" {
				return true
			}
			l := conn.LocalAddr()
			if l == nil {
				// already closed
				return false
			}

			host, _, _ := net.SplitHostPort(l.String())
			if host != laddr && bindInterface == "" {
				log.WithFields(log.Fields{
					"Topic":           "Peer",
					"Key":             remoteAddr,
					"Configured addr": laddr,
					"Addr":            host,
					"BindInterface":   bindInterface,
				}).Info("Mismatched local address")
				return false
			}
			return true
		}(localAddr)

		if !localAddrValid {
			conn.Close()
			return
		}

		log.WithFields(log.Fields{
			"Topic": "Peer",
		}).Debugf("Accepted a new passive connection from:%s", remoteAddr)
		peer.PassConn(conn)
	} else if pg := s.matchLongestDynamicNeighborPrefix(remoteAddr); pg != nil {
		log.WithFields(log.Fields{
			"Topic": "Peer",
		}).Debugf("Accepted a new dynamic neighbor from:%s", remoteAddr)
		rib := s.globalRib
		if pg.Conf.RouteServer.Config.RouteServerClient {
			rib = s.rsRib
		}
		peer := newDynamicPeer(&s.bgpConfig.Global, remoteAddr, pg.Conf, rib, s.policy)
		if peer == nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   remoteAddr,
			}).Infof("Can't create new Dynamic Peer")
			conn.Close()
			return
		}
		//s.addIncoming(peer.fsm.incomingCh)
		peer.fsm.incomingCh = s.incomingCh

		peer.fsm.lock.RLock()
		policy := peer.fsm.pConf.ApplyPolicy
		peer.fsm.lock.RUnlock()
		s.policy.SetPeerPolicy(peer.ID(), policy)
		s.neighborMap[remoteAddr] = peer
		peer.startFSMHandler()
		s.broadcastPeerState(peer, bgp.BGP_FSM_ACTIVE, nil)
		peer.PassConn(conn)
	} else {
		log.WithFields(log.Fields{
			"Topic": "Peer",
		}).Infof("Can't find configuration for a new passive connection from:%s", remoteAddr)
		conn.Close()
	}
}

func sendfsmOutgoingMsg(peer *peer, paths []*table.Path, notification *bgp.BGPMessage, stayIdle bool) {
	peer.fsm.outgoingCh <- &fsmOutgoingMsg{
		Paths:        paths,
		Notification: notification,
		StayIdle:     stayIdle,
	}
}

func isASLoop(peer *peer, path *table.Path) bool {
	for _, as := range path.GetAsList() {
		if as == peer.AS() {
			return true
		}
	}
	return false
}

func clonePathList(pathList []*table.Path) []*table.Path {
	l := make([]*table.Path, 0, len(pathList))
	for _, p := range pathList {
		if p != nil {
			l = append(l, p.Clone(p.IsWithdraw))
		}
	}
	return l
}

func (s *BgpServer) setPathVrfIdMap(paths []*table.Path, m map[uint32]bool) {
	for _, p := range paths {
		switch p.GetRouteFamily() {
		case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
			for _, vrf := range s.globalRib.Vrfs {
				if vrf.Id != 0 && table.CanImportToVrf(vrf, p) {
					m[uint32(vrf.Id)] = true
				}
			}
		default:
			m[zebra.DefaultVrf] = true
		}
	}
}

// Note: the destination would be the same for all the paths passed here
// The wather (only zapi) needs a unique list of vrf IDs
func (s *BgpServer) notifyBestWatcher(best []*table.Path, multipath [][]*table.Path) {
	if table.SelectionOptions.DisableBestPathSelection {
		// Note: If best path selection disabled, no best path to notify.
		return
	}
	m := make(map[uint32]bool)
	clonedM := make([][]*table.Path, len(multipath))
	for i, pathList := range multipath {
		clonedM[i] = clonePathList(pathList)
		if table.UseMultiplePaths.Enabled {
			s.setPathVrfIdMap(clonedM[i], m)
		}
	}
	clonedB := clonePathList(best)
	if !table.UseMultiplePaths.Enabled {
		s.setPathVrfIdMap(clonedB, m)
	}
	w := &watchEventBestPath{PathList: clonedB, MultiPathList: clonedM}
	if len(m) > 0 {
		w.Vrf = m
	}
	s.notifyWatcher(watchEventTypeBestPath, w)
}

func (s *BgpServer) toConfig(peer *peer, getAdvertised bool) *config.Neighbor {
	// create copy which can be access to without mutex
	peer.fsm.lock.RLock()
	conf := *peer.fsm.pConf
	peerAfiSafis := peer.fsm.pConf.AfiSafis
	peerCapMap := peer.fsm.capMap
	peer.fsm.lock.RUnlock()

	conf.AfiSafis = make([]config.AfiSafi, len(peerAfiSafis))
	for i, af := range peerAfiSafis {
		conf.AfiSafis[i] = af
		conf.AfiSafis[i].AddPaths.State.Receive = peer.isAddPathReceiveEnabled(af.State.Family)
		if peer.isAddPathSendEnabled(af.State.Family) {
			conf.AfiSafis[i].AddPaths.State.SendMax = af.AddPaths.State.SendMax
		} else {
			conf.AfiSafis[i].AddPaths.State.SendMax = 0
		}
	}

	remoteCap := make([]bgp.ParameterCapabilityInterface, 0, len(peerCapMap))
	for _, caps := range peerCapMap {
		for _, m := range caps {
			// need to copy all values here
			buf, _ := m.Serialize()
			c, _ := bgp.DecodeCapability(buf)
			remoteCap = append(remoteCap, c)
		}
	}

	conf.State.RemoteCapabilityList = remoteCap

	peer.fsm.lock.RLock()
	conf.State.LocalCapabilityList = capabilitiesFromConfig(peer.fsm.pConf)
	conf.State.SessionState = config.IntToSessionStateMap[int(peer.fsm.state)]
	conf.State.AdminState = config.IntToAdminStateMap[int(peer.fsm.adminState)]
	state := peer.fsm.state
	peer.fsm.lock.RUnlock()

	if state == bgp.BGP_FSM_ESTABLISHED {
		peer.fsm.lock.RLock()
		conf.Transport.State.LocalAddress, conf.Transport.State.LocalPort = peer.fsm.LocalHostPort()
		_, conf.Transport.State.RemotePort = peer.fsm.RemoteHostPort()
		buf, _ := peer.fsm.recvOpen.Serialize()
		// need to copy all values here
		conf.State.ReceivedOpenMessage, _ = bgp.ParseBGPMessage(buf)
		conf.State.RemoteRouterId = peer.fsm.peerInfo.ID.To4().String()
		peer.fsm.lock.RUnlock()
	}
	return &conf
}

func (s *BgpServer) notifyPrePolicyUpdateWatcher(peer *peer, pathList []*table.Path, msg *bgp.BGPMessage, timestamp time.Time, payload []byte) {
	if !s.isWatched(watchEventTypePreUpdate) || peer == nil {
		return
	}

	cloned := clonePathList(pathList)
	if len(cloned) == 0 {
		return
	}
	n := s.toConfig(peer, false)
	peer.fsm.lock.RLock()
	_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	l, _ := peer.fsm.LocalHostPort()
	ev := &watchEventUpdate{
		Message:      msg,
		PeerAS:       peer.fsm.peerInfo.AS,
		LocalAS:      peer.fsm.peerInfo.LocalAS,
		PeerAddress:  peer.fsm.peerInfo.Address,
		LocalAddress: net.ParseIP(l),
		PeerID:       peer.fsm.peerInfo.ID,
		FourBytesAs:  y,
		Timestamp:    timestamp,
		Payload:      payload,
		PostPolicy:   false,
		PathList:     cloned,
		Neighbor:     n,
	}
	peer.fsm.lock.RUnlock()
	s.notifyWatcher(watchEventTypePreUpdate, ev)
}

func (s *BgpServer) notifyPostPolicyUpdateWatcher(peer *peer, pathList []*table.Path) {
	if !s.isWatched(watchEventTypePostUpdate) || peer == nil {
		return
	}

	cloned := clonePathList(pathList)
	if len(cloned) == 0 {
		return
	}
	n := s.toConfig(peer, false)
	peer.fsm.lock.RLock()
	_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	l, _ := peer.fsm.LocalHostPort()
	ev := &watchEventUpdate{
		PeerAS:       peer.fsm.peerInfo.AS,
		LocalAS:      peer.fsm.peerInfo.LocalAS,
		PeerAddress:  peer.fsm.peerInfo.Address,
		LocalAddress: net.ParseIP(l),
		PeerID:       peer.fsm.peerInfo.ID,
		FourBytesAs:  y,
		Timestamp:    cloned[0].GetTimestamp(),
		PostPolicy:   true,
		PathList:     cloned,
		Neighbor:     n,
	}
	peer.fsm.lock.RUnlock()
	s.notifyWatcher(watchEventTypePostUpdate, ev)
}

func (s *BgpServer) notifyMessageWatcher(peer *peer, timestamp time.Time, msg *bgp.BGPMessage, isSent bool) {
	// validation should be done in the caller of this function
	peer.fsm.lock.RLock()
	_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	l, _ := peer.fsm.LocalHostPort()
	ev := &watchEventMessage{
		Message:      msg,
		PeerAS:       peer.fsm.peerInfo.AS,
		LocalAS:      peer.fsm.peerInfo.LocalAS,
		PeerAddress:  peer.fsm.peerInfo.Address,
		LocalAddress: net.ParseIP(l),
		PeerID:       peer.fsm.peerInfo.ID,
		FourBytesAs:  y,
		Timestamp:    timestamp,
		IsSent:       isSent,
	}
	peer.fsm.lock.RUnlock()
	if !isSent {
		s.notifyWatcher(watchEventTypeRecvMsg, ev)
	}
}

func (s *BgpServer) notifyRecvMessageWatcher(peer *peer, timestamp time.Time, msg *bgp.BGPMessage) {
	if peer == nil || !s.isWatched(watchEventTypeRecvMsg) {
		return
	}
	s.notifyMessageWatcher(peer, timestamp, msg, false)
}

func (s *BgpServer) getPossibleBest(peer *peer, family bgp.RouteFamily) []*table.Path {
	if peer.isAddPathSendEnabled(family) {
		return peer.localRib.GetPathList(peer.TableID(), peer.AS(), []bgp.RouteFamily{family})
	}
	return peer.localRib.GetBestPathList(peer.TableID(), peer.AS(), []bgp.RouteFamily{family})
}

func (s *BgpServer) getBestFromLocal(peer *peer, rfList []bgp.RouteFamily) ([]*table.Path, []*table.Path) {
	pathList := []*table.Path{}
	filtered := []*table.Path{}

	if peer.isSecondaryRouteEnabled() {
		for _, family := range peer.toGlobalFamilies(rfList) {
			dsts := s.rsRib.Tables[family].GetDestinations()
			dl := make([]*table.Update, 0, len(dsts))
			for _, d := range dsts {
				l := d.GetAllKnownPathList()
				pl := make([]*table.Path, len(l))
				copy(pl, l)
				u := &table.Update{
					KnownPathList: pl,
				}
				dl = append(dl, u)
			}
			pathList = append(pathList, s.sendSecondaryRoutes(peer, nil, dl)...)
		}
		return pathList, filtered
	}

	for _, family := range peer.toGlobalFamilies(rfList) {
		for _, path := range s.getPossibleBest(peer, family) {
			if p := s.filterpath(peer, path, nil); p != nil {
				pathList = append(pathList, p)
			} else {
				filtered = append(filtered, path)
			}
		}
	}
	if peer.isGracefulRestartEnabled() {
		for _, family := range rfList {
			pathList = append(pathList, table.NewEOR(family))
		}
	}
	return pathList, filtered
}

func needToAdvertise(peer *peer) bool {
	peer.fsm.lock.RLock()
	notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
	localRestarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
	peer.fsm.lock.RUnlock()
	if notEstablished {
		return false
	}
	if localRestarting {
		peer.fsm.lock.RLock()
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.fsm.pConf.State.NeighborAddress,
		}).Debug("now syncing, suppress sending updates")
		peer.fsm.lock.RUnlock()
		return false
	}
	return true
}

func (s *BgpServer) propagateUpdate(peer *peer, pathList []*table.Path) {
	rs := peer != nil && peer.isRouteServerClient()
	vrf := false
	if peer != nil {
		peer.fsm.lock.RLock()
		vrf = !rs && peer.fsm.pConf.Config.Vrf != ""
		peer.fsm.lock.RUnlock()
	}

	tableId := table.GLOBAL_RIB_NAME
	rib := s.globalRib
	if rs {
		tableId = peer.TableID()
		rib = s.rsRib
	}

	for _, path := range pathList {
		if vrf {
			peer.fsm.lock.RLock()
			peerVrf := peer.fsm.pConf.Config.Vrf
			peer.fsm.lock.RUnlock()
			path = path.ToGlobal(rib.Vrfs[peerVrf])
		}

		policyOptions := &table.PolicyOptions{
			Validate: s.roaTable.Validate,
		}

		if !rs && peer != nil {
			peer.fsm.lock.RLock()
			policyOptions.Info = peer.fsm.peerInfo
			peer.fsm.lock.RUnlock()
		}

		if p := s.policy.ApplyPolicy(tableId, table.POLICY_DIRECTION_IMPORT, path, policyOptions); p != nil {
			path = p
		} else {
			path = path.Clone(true)
		}

		if !rs {
			s.notifyPostPolicyUpdateWatcher(peer, []*table.Path{path})

			// RFC4684 Constrained Route Distribution 6. Operation
			//
			// When a BGP speaker receives a BGP UPDATE that advertises or withdraws
			// a given Route Target membership NLRI, it should examine the RIB-OUTs
			// of VPN NLRIs and re-evaluate the advertisement status of routes that
			// match the Route Target in question.
			//
			// A BGP speaker should generate the minimum set of BGP VPN route
			// updates (advertisements and/or withdraws) necessary to transition
			// between the previous and current state of the route distribution
			// graph that is derived from Route Target membership information.
			if peer != nil && path != nil && path.GetRouteFamily() == bgp.RF_RTC_UC {
				rt := path.GetNlri().(*bgp.RouteTargetMembershipNLRI).RouteTarget
				fs := make([]bgp.RouteFamily, 0, len(peer.negotiatedRFList()))
				for _, f := range peer.negotiatedRFList() {
					if f != bgp.RF_RTC_UC {
						fs = append(fs, f)
					}
				}
				var candidates []*table.Path
				if path.IsWithdraw {
					// Note: The paths to be withdrawn are filtered because the
					// given RT on RTM NLRI is already removed from adj-RIB-in.
					_, candidates = s.getBestFromLocal(peer, fs)
				} else {
					// https://github.com/osrg/gobgp/issues/1777
					// Ignore duplicate Membership announcements
					membershipsForSource := s.globalRib.GetPathListWithSource(table.GLOBAL_RIB_NAME, []bgp.RouteFamily{bgp.RF_RTC_UC}, path.GetSource())
					found := false
					for _, membership := range membershipsForSource {
						if membership.GetNlri().(*bgp.RouteTargetMembershipNLRI).RouteTarget.String() == rt.String() {
							found = true
							break
						}
					}
					if !found {
						candidates = s.globalRib.GetBestPathList(peer.TableID(), 0, fs)
					}
				}
				paths := make([]*table.Path, 0, len(candidates))
				for _, p := range candidates {
					for _, ext := range p.GetExtCommunities() {
						if rt == nil || ext.String() == rt.String() {
							if path.IsWithdraw {
								p = p.Clone(true)
							}
							paths = append(paths, p)
							break
						}
					}
				}
				if path.IsWithdraw {
					// Skips filtering because the paths are already filtered
					// and the withdrawal does not need the path attributes.
				} else {
					paths = s.processOutgoingPaths(peer, paths, nil)
				}
				sendfsmOutgoingMsg(peer, paths, nil, false)
			}
		}

		if dsts := rib.Update(path); len(dsts) > 0 {
			s.propagateUpdateToNeighbors(peer, path, dsts, true)
		}
	}
}

func (s *BgpServer) propagateUpdateToNeighbors(source *peer, newPath *table.Path, dsts []*table.Update, needOld bool) {
	if table.SelectionOptions.DisableBestPathSelection {
		return
	}
	var gBestList, gOldList, bestList, oldList []*table.Path
	var mpathList [][]*table.Path
	if source == nil || !source.isRouteServerClient() {
		gBestList, gOldList, mpathList = dstsToPaths(table.GLOBAL_RIB_NAME, 0, dsts)
		s.notifyBestWatcher(gBestList, mpathList)
	}
	family := newPath.GetRouteFamily()
	for _, targetPeer := range s.neighborMap {
		if (source == nil && targetPeer.isRouteServerClient()) || (source != nil && source.isRouteServerClient() != targetPeer.isRouteServerClient()) {
			continue
		}
		f := func() bgp.RouteFamily {
			targetPeer.fsm.lock.RLock()
			peerVrf := targetPeer.fsm.pConf.Config.Vrf
			targetPeer.fsm.lock.RUnlock()
			if peerVrf != "" {
				switch family {
				case bgp.RF_IPv4_VPN:
					return bgp.RF_IPv4_UC
				case bgp.RF_IPv6_VPN:
					return bgp.RF_IPv6_UC
				case bgp.RF_FS_IPv4_VPN:
					return bgp.RF_FS_IPv4_UC
				case bgp.RF_FS_IPv6_VPN:
					return bgp.RF_FS_IPv6_UC
				}
			}
			return family
		}()
		if targetPeer.isAddPathSendEnabled(f) {
			if newPath.IsWithdraw {
				bestList = func() []*table.Path {
					l := make([]*table.Path, 0, len(dsts))
					for _, d := range dsts {
						l = append(l, d.GetWithdrawnPath()...)
					}
					return l
				}()
			} else {
				bestList = []*table.Path{newPath}
				if newPath.GetRouteFamily() == bgp.RF_RTC_UC {
					// we assumes that new "path" nlri was already sent before. This assumption avoids the
					// infinite UPDATE loop between Route Reflector and its clients.
					for _, old := range dsts[0].OldKnownPathList {
						if old.IsLocal() {
							bestList = []*table.Path{}
							break
						}
					}
				}
			}
			oldList = nil
		} else if targetPeer.isRouteServerClient() {
			if targetPeer.isSecondaryRouteEnabled() {
				if paths := s.sendSecondaryRoutes(targetPeer, newPath, dsts); len(paths) > 0 {
					sendfsmOutgoingMsg(targetPeer, paths, nil, false)
				}
				continue
			}
			bestList, oldList, _ = dstsToPaths(targetPeer.TableID(), targetPeer.AS(), dsts)
		} else {
			bestList = gBestList
			oldList = gOldList
		}
		if !needOld {
			oldList = nil
		}
		if paths := s.processOutgoingPaths(targetPeer, bestList, oldList); len(paths) > 0 {
			sendfsmOutgoingMsg(targetPeer, paths, nil, false)
		}
	}
}

func getMacMobilityExtendedCommunity(etag uint32, mac net.HardwareAddr, evpnPaths []*table.Path) *bgp.MacMobilityExtended {
	seqs := make([]struct {
		seq     int
		isLocal bool
	}, 0)

	for _, path := range evpnPaths {
		nlri := path.GetNlri().(*bgp.EVPNNLRI)
		target, ok := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
		if !ok {
			continue
		}
		if target.ETag == etag && bytes.Equal(target.MacAddress, mac) {
			found := false
			for _, ec := range path.GetExtCommunities() {
				if t, st := ec.GetTypes(); t == bgp.EC_TYPE_EVPN && st == bgp.EC_SUBTYPE_MAC_MOBILITY {
					seqs = append(seqs, struct {
						seq     int
						isLocal bool
					}{int(ec.(*bgp.MacMobilityExtended).Sequence), path.IsLocal()})
					found = true
					break
				}
			}

			if !found {
				seqs = append(seqs, struct {
					seq     int
					isLocal bool
				}{-1, path.IsLocal()})
			}
		}
	}

	if len(seqs) > 0 {
		newSeq := -2
		var isLocal bool
		for _, seq := range seqs {
			if seq.seq > newSeq {
				newSeq = seq.seq
				isLocal = seq.isLocal
			}
		}

		if !isLocal {
			newSeq += 1
		}

		if newSeq != -1 {
			return &bgp.MacMobilityExtended{
				Sequence: uint32(newSeq),
			}
		}
	}
	return nil
}

func familiesForSoftreset(peer *peer, family bgp.RouteFamily) []bgp.RouteFamily {
	if family == bgp.RouteFamily(0) {
		configured := peer.configuredRFlist()
		families := make([]bgp.RouteFamily, 0, len(configured))
		for _, f := range configured {
			if f != bgp.RF_RTC_UC {
				families = append(families, f)
			}
		}
		return families
	}
	return []bgp.RouteFamily{family}
}

func (s *BgpServer) softResetIn(addr string, family bgp.RouteFamily) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		s.propagateUpdate(peer, peer.adjRibIn.PathList(familiesForSoftreset(peer, family), true))
	}
	return err
}

func (s *BgpServer) softResetOut(addr string, family bgp.RouteFamily, deferral bool) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		peer.fsm.lock.RLock()
		notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
		peer.fsm.lock.RUnlock()
		if notEstablished {
			continue
		}
		families := familiesForSoftreset(peer, family)

		if deferral {
			if family == bgp.RouteFamily(0) {
				families = peer.configuredRFlist()
			}
			peer.fsm.lock.RLock()
			_, y := peer.fsm.rfMap[bgp.RF_RTC_UC]
			c := peer.fsm.pConf.GetAfiSafi(bgp.RF_RTC_UC)
			restarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
			peer.fsm.lock.RUnlock()
			if restarting {
				peer.fsm.lock.Lock()
				peer.fsm.pConf.GracefulRestart.State.LocalRestarting = false
				peer.fsm.lock.Unlock()
				log.WithFields(log.Fields{
					"Topic":    "Peer",
					"Key":      peer.ID(),
					"Families": families,
				}).Debug("deferral timer expired")
			} else if y && !c.MpGracefulRestart.State.EndOfRibReceived {
				log.WithFields(log.Fields{
					"Topic":    "Peer",
					"Key":      peer.ID(),
					"Families": families,
				}).Debug("route-target deferral timer expired")
			} else {
				continue
			}
		}

		pathList, _ := s.getBestFromLocal(peer, families)
		if len(pathList) > 0 {
			if deferral {
				pathList = func() []*table.Path {
					l := make([]*table.Path, 0, len(pathList))
					for _, p := range pathList {
						if !p.IsWithdraw {
							l = append(l, p)
						}
					}
					return l
				}()
			}
			sendfsmOutgoingMsg(peer, pathList, nil, false)
		}
	}
	return nil
}

func (s *BgpServer) sResetIn(addr string, family bgp.RouteFamily) error {
	log.WithFields(log.Fields{
		"Topic": "Operation",
		"Key":   addr,
	}).Info("Neighbor soft reset in")
	return s.softResetIn(addr, family)
}

func (s *BgpServer) sResetOut(addr string, family bgp.RouteFamily) error {
	log.WithFields(log.Fields{
		"Topic": "Operation",
		"Key":   addr,
	}).Info("Neighbor soft reset out")
	return s.softResetOut(addr, family, false)
}

func (s *BgpServer) sReset(addr string, family bgp.RouteFamily) error {
	log.WithFields(log.Fields{
		"Topic": "Operation",
		"Key":   addr,
	}).Info("Neighbor soft reset")
	err := s.softResetIn(addr, family)
	if err != nil {
		return err
	}
	return s.softResetOut(addr, family, false)
}

func (s *BgpServer) validateTable(r *table.Table) (v map[*table.Path]*table.Validation) {
	//if s.roaManager.enabled() {
	v = make(map[*table.Path]*table.Validation, len(r.GetDestinations()))
	for _, d := range r.GetDestinations() {
		for _, p := range d.GetAllKnownPathList() {
			v[p] = s.roaTable.Validate(p)
		}
	}
	//}
	return
}

func (s *BgpServer) getRib(addr string, family bgp.RouteFamily, prefixes []*table.LookupPrefix) (rib *table.Table, v map[*table.Path]*table.Validation, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		id := table.GLOBAL_RIB_NAME
		as := uint32(0)
		if len(addr) > 0 {
			peer, ok := s.neighborMap[addr]
			if !ok {
				return fmt.Errorf("neighbor that has %v doesn't exist", addr)
			}
			if !peer.isRouteServerClient() {
				return fmt.Errorf("neighbor %v doesn't have local rib", addr)
			}
			id = peer.ID()
			as = peer.AS()
			m = s.rsRib
		}
		af := bgp.RouteFamily(family)
		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}
		rib, err = tbl.Select(table.TableSelectOption{ID: id, AS: as, LookupPrefixes: prefixes})
		v = s.validateTable(rib)
		return err
	}, true)
	return
}

func (s *BgpServer) getVrfRib(name string, family bgp.RouteFamily, prefixes []*table.LookupPrefix) (rib *table.Table, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		vrfs := m.Vrfs
		if _, ok := vrfs[name]; !ok {
			return fmt.Errorf("vrf %s not found", name)
		}
		var af bgp.RouteFamily
		switch family {
		case bgp.RF_IPv4_UC:
			af = bgp.RF_IPv4_VPN
		case bgp.RF_IPv6_UC:
			af = bgp.RF_IPv6_VPN
		case bgp.RF_FS_IPv4_UC:
			af = bgp.RF_FS_IPv4_VPN
		case bgp.RF_FS_IPv6_UC:
			af = bgp.RF_FS_IPv6_VPN
		case bgp.RF_EVPN:
			af = bgp.RF_EVPN
		}
		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}
		rib, err = tbl.Select(table.TableSelectOption{VRF: vrfs[name], LookupPrefixes: prefixes})
		return err
	}, true)
	return
}

func (s *BgpServer) getAdjRib(addr string, family bgp.RouteFamily, in bool, enableFiltered bool, prefixes []*table.LookupPrefix) (rib *table.Table, filtered map[string]*table.Path, v map[*table.Path]*table.Validation, err error) {
	err = s.mgmtOperation(func() error {
		peer, ok := s.neighborMap[addr]
		if !ok {
			return fmt.Errorf("neighbor that has %v doesn't exist", addr)
		}
		id := peer.ID()
		as := peer.AS()

		var adjRib *table.AdjRib
		filtered = make(map[string]*table.Path)
		if in {
			adjRib = peer.adjRibIn
			if enableFiltered {
				for _, path := range peer.adjRibIn.PathList([]bgp.RouteFamily{family}, true) {
					options := &table.PolicyOptions{
						Validate: s.roaTable.Validate,
					}
					if s.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_IMPORT, path, options) == nil {
						filtered[path.GetNlri().String()] = path
					}
				}
			}
		} else {
			adjRib = table.NewAdjRib(peer.configuredRFlist())
			if enableFiltered {
				for _, path := range s.getPossibleBest(peer, family) {
					path, options, stop := s.prePolicyFilterpath(peer, path, nil)
					if stop {
						continue
					}
					options.Validate = s.roaTable.Validate
					p := peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, path, options)
					if p == nil {
						filtered[path.GetNlri().String()] = path
					}
					adjRib.UpdateAdjRibOut([]*table.Path{path})
				}
			} else {
				accepted, _ := s.getBestFromLocal(peer, peer.configuredRFlist())
				adjRib.UpdateAdjRibOut(accepted)
			}
		}
		rib, err = adjRib.Select(family, false, table.TableSelectOption{ID: id, AS: as, LookupPrefixes: prefixes})
		v = s.validateTable(rib)
		return err
	}, true)
	return
}

func (s *BgpServer) getRibInfo(addr string, family bgp.RouteFamily) (info *table.TableInfo, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		id := table.GLOBAL_RIB_NAME
		as := uint32(0)
		if len(addr) > 0 {
			peer, ok := s.neighborMap[addr]
			if !ok {
				return fmt.Errorf("neighbor that has %v doesn't exist", addr)
			}
			if !peer.isRouteServerClient() {
				return fmt.Errorf("neighbor %v doesn't have local rib", addr)
			}
			id = peer.ID()
			as = peer.AS()
			m = s.rsRib
		}

		af := bgp.RouteFamily(family)
		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}

		info = tbl.Info(table.TableInfoOptions{ID: id, AS: as})

		return err
	}, true)
	return
}

func (s *BgpServer) getAdjRibInfo(addr string, family bgp.RouteFamily, in bool) (info *table.TableInfo, err error) {
	err = s.mgmtOperation(func() error {
		peer, ok := s.neighborMap[addr]
		if !ok {
			return fmt.Errorf("neighbor that has %v doesn't exist", addr)
		}

		var adjRib *table.AdjRib
		if in {
			adjRib = peer.adjRibIn
		} else {
			adjRib = table.NewAdjRib(peer.configuredRFlist())
			accepted, _ := s.getBestFromLocal(peer, peer.configuredRFlist())
			adjRib.UpdateAdjRibOut(accepted)
		}
		info, err = adjRib.TableInfo(family)
		return err
	}, true)
	return
}

func (s *BgpServer) getVrfRibInfo(name string, family bgp.RouteFamily) (info *table.TableInfo, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		vrfs := m.Vrfs
		if _, ok := vrfs[name]; !ok {
			return fmt.Errorf("vrf %s not found", name)
		}

		var af bgp.RouteFamily
		switch family {
		case bgp.RF_IPv4_UC:
			af = bgp.RF_IPv4_VPN
		case bgp.RF_IPv6_UC:
			af = bgp.RF_IPv6_VPN
		case bgp.RF_FS_IPv4_UC:
			af = bgp.RF_FS_IPv4_VPN
		case bgp.RF_FS_IPv6_UC:
			af = bgp.RF_FS_IPv6_VPN
		case bgp.RF_EVPN:
			af = bgp.RF_EVPN
		}

		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}

		info = tbl.Info(table.TableInfoOptions{VRF: vrfs[name]})

		return err
	}, true)
	return
}

func (s *BgpServer) GetTable(ctx context.Context, r *api.GetTableRequest) (*api.GetTableResponse, error) {
	if r == nil || r.Family == nil {
		return nil, fmt.Errorf("nil request")
	}
	family := bgp.RouteFamily(0)
	if r.Family != nil {
		family = bgp.AfiSafiToRouteFamily(uint16(r.Family.Afi), uint8(r.Family.Safi))
	}
	var in bool
	var err error
	var info *table.TableInfo
	switch r.TableType {
	case api.TableType_GLOBAL, api.TableType_LOCAL:
		info, err = s.getRibInfo(r.Name, family)
	case api.TableType_ADJ_IN:
		in = true
		fallthrough
	case api.TableType_ADJ_OUT:
		info, err = s.getAdjRibInfo(r.Name, family, in)
	case api.TableType_VRF:
		info, err = s.getVrfRibInfo(r.Name, family)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", r.TableType)
	}

	if err != nil {
		return nil, err
	}

	return &api.GetTableResponse{
		NumDestination: uint64(info.NumDestination),
		NumPath:        uint64(info.NumPath),
		NumAccepted:    uint64(info.NumAccepted),
	}, nil
}

func (s *BgpServer) sendNotification(op, addr string, subcode uint8, data []byte) error {
	log.WithFields(log.Fields{
		"Topic": "Operation",
		"Key":   addr,
	}).Info(op)

	peers, err := s.addrToPeers(addr)
	if err == nil {
		m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, subcode, data)
		for _, peer := range peers {
			sendfsmOutgoingMsg(peer, nil, m, false)
		}
	}
	return err
}

func (s *BgpServer) setAdminState(addr, communication string, enable bool) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		f := func(stateOp *adminStateOperation, message string) {
			select {
			case peer.fsm.adminStateCh <- *stateOp:
				peer.fsm.lock.RLock()
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   peer.fsm.pConf.State.NeighborAddress,
				}).Debug(message)
				peer.fsm.lock.RUnlock()
			default:
				peer.fsm.lock.RLock()
				log.Warning("previous request is still remaining. : ", peer.fsm.pConf.State.NeighborAddress)
				peer.fsm.lock.RUnlock()
			}
		}
		if enable {
			f(&adminStateOperation{adminStateUp, nil}, "adminStateUp requested")
		} else {
			f(&adminStateOperation{adminStateDown, newAdministrativeCommunication(communication)}, "adminStateDown requested")
		}
	}
	return nil
}

func (s *BgpServer) SetLogLevel(ctx context.Context, r *api.SetLogLevelRequest) error {
	prevLevel := log.GetLevel()
	newLevel := log.Level(r.Level)
	if prevLevel == newLevel {
		log.WithFields(log.Fields{
			"Topic": "Config",
		}).Infof("Logging level unchanged -- level already set to %v", newLevel)
	} else {
		log.SetLevel(newLevel)
		log.WithFields(log.Fields{
			"Topic": "Config",
		}).Infof("Logging level changed -- prev: %v, new: %v", prevLevel, newLevel)
	}
	return nil
}
