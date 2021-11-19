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
	"context"
	"fmt"
	api "github.com/osrg/gobgp/api"
	"k8s.io/klog/v2"
	"net"
	"time"

	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/pkg/packet/bgp"

	log "github.com/sirupsen/logrus"
)

const (
	flopThreshold = time.Second * 30
)

type peerGroup struct {
	Conf             *config.PeerGroup
	members          map[string]config.Neighbor
	dynamicNeighbors map[string]*config.DynamicNeighbor
}

func newPeerGroup(c *config.PeerGroup) *peerGroup {
	return &peerGroup{
		Conf:             c,
		members:          make(map[string]config.Neighbor),
		dynamicNeighbors: make(map[string]*config.DynamicNeighbor),
	}
}

func (pg *peerGroup) AddMember(c config.Neighbor) {
	pg.members[c.State.NeighborAddress] = c
}

func (pg *peerGroup) DeleteMember(c config.Neighbor) {
	delete(pg.members, c.State.NeighborAddress)
}

func (pg *peerGroup) AddDynamicNeighbor(c *config.DynamicNeighbor) {
	pg.dynamicNeighbors[c.Config.Prefix] = c
}

func (pg *peerGroup) DeleteDynamicNeighbor(prefix string) {
	delete(pg.dynamicNeighbors, prefix)
}

func newDynamicPeer(g *config.Global, neighborAddress string, pg *config.PeerGroup, loc *table.TableManager, policy *table.RoutingPolicy) *peer {
	conf := config.Neighbor{
		Config: config.NeighborConfig{
			PeerGroup: pg.Config.PeerGroupName,
		},
		State: config.NeighborState{
			NeighborAddress: neighborAddress,
		},
		Transport: config.Transport{
			Config: config.TransportConfig{
				PassiveMode: true,
			},
		},
	}
	if err := config.OverwriteNeighborConfigWithPeerGroup(&conf, pg); err != nil {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   neighborAddress,
		}).Debugf("Can't overwrite neighbor config: %s", err)
		return nil
	}
	if err := config.SetDefaultNeighborConfigValues(&conf, pg, g); err != nil {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   neighborAddress,
		}).Debugf("Can't set default config: %s", err)
		return nil
	}
	peer := newPeer(g, &conf, loc, policy)
	peer.fsm.lock.Lock()
	peer.fsm.state = bgp.BGP_FSM_ACTIVE
	peer.fsm.lock.Unlock()
	return peer
}

type peer struct {
	tableId           string
	fsm               *fsm
	adjRibIn          *table.AdjRib
	policy            *table.RoutingPolicy
	localRib          *table.TableManager
	prefixLimitWarned map[bgp.RouteFamily]bool
	llgrEndChs        []chan struct{}
}

func newPeer(g *config.Global, conf *config.Neighbor, loc *table.TableManager, policy *table.RoutingPolicy) *peer {
	peer := &peer{
		localRib:          loc,
		policy:            policy,
		fsm:               newFSM(g, conf),
		prefixLimitWarned: make(map[bgp.RouteFamily]bool),
	}
	if peer.isRouteServerClient() {
		peer.tableId = conf.State.NeighborAddress
	} else {
		peer.tableId = table.GLOBAL_RIB_NAME
	}
	rfs, _ := config.AfiSafis(conf.AfiSafis).ToRfList()
	peer.adjRibIn = table.NewAdjRib(rfs)
	return peer
}

func (peer *peer) AS() uint32 {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.State.PeerAs
}

func (peer *peer) ID() string {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.State.NeighborAddress
}

func (peer *peer) RouterID() string {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	if peer.fsm.peerInfo.ID != nil {
		return peer.fsm.peerInfo.ID.String()
	}
	return ""
}

func (peer *peer) TableID() string {
	return peer.tableId
}

func (peer *peer) isIBGPPeer() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.State.PeerType == config.PEER_TYPE_INTERNAL
}

func (peer *peer) isRouteServerClient() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.RouteServer.Config.RouteServerClient
}

func (peer *peer) isSecondaryRouteEnabled() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.RouteServer.Config.RouteServerClient && peer.fsm.pConf.RouteServer.Config.SecondaryRoute
}

func (peer *peer) isRouteReflectorClient() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.RouteReflector.Config.RouteReflectorClient
}

func (peer *peer) isGracefulRestartEnabled() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.GracefulRestart.State.Enabled
}

func (peer *peer) getAddPathMode(family bgp.RouteFamily) bgp.BGPAddPathMode {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	if mode, y := peer.fsm.rfMap[family]; y {
		return mode
	}
	return bgp.BGP_ADD_PATH_NONE
}

func (peer *peer) isAddPathReceiveEnabled(family bgp.RouteFamily) bool {
	return (peer.getAddPathMode(family) & bgp.BGP_ADD_PATH_RECEIVE) > 0
}

func (peer *peer) isAddPathSendEnabled(family bgp.RouteFamily) bool {
	return (peer.getAddPathMode(family) & bgp.BGP_ADD_PATH_SEND) > 0
}

func (peer *peer) isDynamicNeighbor() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.Config.NeighborAddress == "" && peer.fsm.pConf.Config.NeighborInterface == ""
}

func (peer *peer) recvedAllEOR() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	for _, a := range peer.fsm.pConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && !s.EndOfRibReceived {
			return false
		}
	}
	return true
}

func (peer *peer) configuredRFlist() []bgp.RouteFamily {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	rfs, _ := config.AfiSafis(peer.fsm.pConf.AfiSafis).ToRfList()
	return rfs
}

func (peer *peer) negotiatedRFList() []bgp.RouteFamily {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	l := make([]bgp.RouteFamily, 0, len(peer.fsm.rfMap))
	for family := range peer.fsm.rfMap {
		l = append(l, family)
	}
	return l
}

func (peer *peer) toGlobalFamilies(families []bgp.RouteFamily) []bgp.RouteFamily {
	id := peer.ID()
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	if peer.fsm.pConf.Config.Vrf != "" {
		fs := make([]bgp.RouteFamily, 0, len(families))
		for _, f := range families {
			switch f {
			case bgp.RF_IPv4_UC:
				fs = append(fs, bgp.RF_IPv4_VPN)
			case bgp.RF_IPv6_UC:
				fs = append(fs, bgp.RF_IPv6_VPN)
			case bgp.RF_FS_IPv4_UC:
				fs = append(fs, bgp.RF_FS_IPv4_VPN)
			case bgp.RF_FS_IPv6_UC:
				fs = append(fs, bgp.RF_FS_IPv6_VPN)
			default:
				log.WithFields(log.Fields{
					"Topic":  "Peer",
					"Key":    id,
					"Family": f,
					"VRF":    peer.fsm.pConf.Config.Vrf,
				}).Warn("invalid family configured for neighbor with vrf")
			}
		}
		families = fs
	}
	return families
}

func classifyFamilies(all, part []bgp.RouteFamily) ([]bgp.RouteFamily, []bgp.RouteFamily) {
	a := []bgp.RouteFamily{}
	b := []bgp.RouteFamily{}
	for _, f := range all {
		p := true
		for _, g := range part {
			if f == g {
				p = false
				a = append(a, f)
				break
			}
		}
		if p {
			b = append(b, f)
		}
	}
	return a, b
}

func (peer *peer) forwardingPreservedFamilies() ([]bgp.RouteFamily, []bgp.RouteFamily) {
	peer.fsm.lock.RLock()
	list := []bgp.RouteFamily{}
	for _, a := range peer.fsm.pConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received {
			list = append(list, a.State.Family)
		}
	}
	peer.fsm.lock.RUnlock()
	return classifyFamilies(peer.configuredRFlist(), list)
}

func (peer *peer) llgrFamilies() ([]bgp.RouteFamily, []bgp.RouteFamily) {
	peer.fsm.lock.RLock()
	list := []bgp.RouteFamily{}
	for _, a := range peer.fsm.pConf.AfiSafis {
		if a.LongLivedGracefulRestart.State.Enabled {
			list = append(list, a.State.Family)
		}
	}
	peer.fsm.lock.RUnlock()
	return classifyFamilies(peer.configuredRFlist(), list)
}

func (peer *peer) isLLGREnabledFamily(family bgp.RouteFamily) bool {
	peer.fsm.lock.RLock()
	llgrEnabled := peer.fsm.pConf.GracefulRestart.Config.LongLivedEnabled
	peer.fsm.lock.RUnlock()
	if !llgrEnabled {
		return false
	}
	fs, _ := peer.llgrFamilies()
	for _, f := range fs {
		if f == family {
			return true
		}
	}
	return false
}

func (peer *peer) llgrRestartTime(family bgp.RouteFamily) uint32 {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	for _, a := range peer.fsm.pConf.AfiSafis {
		if a.State.Family == family {
			return a.LongLivedGracefulRestart.State.PeerRestartTime
		}
	}
	return 0
}

func (peer *peer) llgrRestartTimerExpired(family bgp.RouteFamily) bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	all := true
	for _, a := range peer.fsm.pConf.AfiSafis {
		if a.State.Family == family {
			a.LongLivedGracefulRestart.State.PeerRestartTimerExpired = true
		}
		s := a.LongLivedGracefulRestart.State
		if s.Received && !s.PeerRestartTimerExpired {
			all = false
		}
	}
	return all
}

func (peer *peer) markLLGRStale(fs []bgp.RouteFamily) []*table.Path {
	return peer.adjRibIn.MarkLLGRStaleOrDrop(fs)
}

func (peer *peer) stopPeerRestarting() {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
	for _, ch := range peer.llgrEndChs {
		close(ch)
	}
	peer.llgrEndChs = make([]chan struct{}, 0)

}

func (peer *peer) filterPathFromSourcePeer(path, old *table.Path) *table.Path {
	// Consider 3 peers - A, B, C and prefix P originated by C. Parallel eBGP
	// sessions exist between A & B, and both have a single session with C.
	//
	// When A receives the withdraw from C, we enter this func for each peer of
	// A, with the following:
	// peer: [C, B #1, B #2]
	// path: new best for P facing B
	// old: old best for P facing C
	//
	// Our comparison between peer identifier and path source ID must be router
	// ID-based (not neighbor address), otherwise we will return early. If we
	// return early for one of the two sessions facing B
	// (whichever is not the new best path), we fail to send a withdraw towards
	// B, and the route is "stuck".
	// TODO: considerations for RFC6286
	if peer.RouterID() != path.GetSource().ID.String() {
		return path
	}

	// Note: Multiple paths having the same prefix could exist the withdrawals
	// list in the case of Route Server setup with import policies modifying
	// paths. In such case, gobgp sends duplicated update messages; withdraw
	// messages for the same prefix.
	if !peer.isRouteServerClient() {
		if peer.isRouteReflectorClient() && path.GetRouteFamily() == bgp.RF_RTC_UC {
			// When the peer is a Route Reflector client and the given path
			// contains the Route Tartget Membership NLRI, the path should not
			// be withdrawn in order to signal the client to distribute routes
			// with the specific RT to Route Reflector.
			return path
		} else if !path.IsWithdraw && old != nil && old.GetSource().Address.String() != peer.ID() {
			// Say, peer A and B advertized same prefix P, and best path
			// calculation chose a path from B as best. When B withdraws prefix
			// P, best path calculation chooses the path from A as best. For
			// peers other than A, this path should be advertised (as implicit
			// withdrawal). However for A, we should advertise the withdrawal
			// path. Thing is same when peer A and we advertized prefix P (as
			// local route), then, we withdraws the prefix.
			return old.Clone(true)
		}
	}
	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Key":   peer.ID(),
		"Data":  path,
	}).Debug("From me, ignore.")
	return nil
}

func (peer *peer) doPrefixLimit(k bgp.RouteFamily, c *config.PrefixLimitConfig) *bgp.BGPMessage {
	if maxPrefixes := int(c.MaxPrefixes); maxPrefixes > 0 {
		count := peer.adjRibIn.Count([]bgp.RouteFamily{k})
		pct := int(c.ShutdownThresholdPct)
		if pct > 0 && !peer.prefixLimitWarned[k] && count > (maxPrefixes*pct/100) {
			peer.prefixLimitWarned[k] = true
			log.WithFields(log.Fields{
				"Topic":         "Peer",
				"Key":           peer.ID(),
				"AddressFamily": k.String(),
			}).Warnf("prefix limit %d%% reached", pct)
		}
		if count > maxPrefixes {
			log.WithFields(log.Fields{
				"Topic":         "Peer",
				"Key":           peer.ID(),
				"AddressFamily": k.String(),
			}).Warnf("prefix limit reached")
			return bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED, nil)
		}
	}
	return nil

}

func (peer *peer) updatePrefixLimitConfig(c []config.AfiSafi) error {
	peer.fsm.lock.RLock()
	x := peer.fsm.pConf.AfiSafis
	peer.fsm.lock.RUnlock()
	y := c
	if len(x) != len(y) {
		return fmt.Errorf("changing supported afi-safi is not allowed")
	}
	m := make(map[bgp.RouteFamily]config.PrefixLimitConfig)
	for _, e := range x {
		m[e.State.Family] = e.PrefixLimit.Config
	}
	for _, e := range y {
		if p, ok := m[e.State.Family]; !ok {
			return fmt.Errorf("changing supported afi-safi is not allowed")
		} else if !p.Equal(&e.PrefixLimit.Config) {
			log.WithFields(log.Fields{
				"Topic":                   "Peer",
				"Key":                     peer.ID(),
				"AddressFamily":           e.Config.AfiSafiName,
				"OldMaxPrefixes":          p.MaxPrefixes,
				"NewMaxPrefixes":          e.PrefixLimit.Config.MaxPrefixes,
				"OldShutdownThresholdPct": p.ShutdownThresholdPct,
				"NewShutdownThresholdPct": e.PrefixLimit.Config.ShutdownThresholdPct,
			}).Warnf("update prefix limit configuration")
			peer.prefixLimitWarned[e.State.Family] = false
			if msg := peer.doPrefixLimit(e.State.Family, &e.PrefixLimit.Config); msg != nil {
				sendfsmOutgoingMsg(peer, nil, msg, true)
			}
		}
	}
	peer.fsm.lock.Lock()
	peer.fsm.pConf.AfiSafis = c
	peer.fsm.lock.Unlock()
	return nil
}

func (peer *peer) handleUpdate(e *fsmMsg) ([]*table.Path, []bgp.RouteFamily, *bgp.BGPMessage) {
	m := e.MsgData.(*bgp.BGPMessage)
	update := m.Body.(*bgp.BGPUpdate)
	log.WithFields(log.Fields{
		"Topic":       "Peer",
		"Key":         peer.fsm.pConf.State.NeighborAddress,
		"nlri":        update.NLRI,
		"withdrawals": update.WithdrawnRoutes,
		"attributes":  update.PathAttributes,
	}).Debug("received update")
	peer.fsm.lock.Lock()
	peer.fsm.pConf.Timers.State.UpdateRecvTime = time.Now().Unix()
	peer.fsm.lock.Unlock()
	if len(e.PathList) > 0 {
		paths := make([]*table.Path, 0, len(e.PathList))
		eor := []bgp.RouteFamily{}
		for _, path := range e.PathList {
			if path.IsEOR() {
				family := path.GetRouteFamily()
				log.WithFields(log.Fields{
					"Topic":         "Peer",
					"Key":           peer.ID(),
					"AddressFamily": family,
				}).Debug("EOR received")
				eor = append(eor, family)
				continue
			}
			// RFC4271 9.1.2 Phase 2: Route Selection
			//
			// If the AS_PATH attribute of a BGP route contains an AS loop, the BGP
			// route should be excluded from the Phase 2 decision function.
			if aspath := path.GetAsPath(); aspath != nil {
				peer.fsm.lock.RLock()
				localAS := peer.fsm.peerInfo.LocalAS
				allowOwnAS := int(peer.fsm.pConf.AsPathOptions.Config.AllowOwnAs)
				peer.fsm.lock.RUnlock()
				if hasOwnASLoop(localAS, allowOwnAS, aspath) {
					path.SetRejected(true)
					continue
				}
			}
			// RFC4456 8. Avoiding Routing Information Loops
			// A router that recognizes the ORIGINATOR_ID attribute SHOULD
			// ignore a route received with its BGP Identifier as the ORIGINATOR_ID.
			isIBGPPeer := peer.isIBGPPeer()
			peer.fsm.lock.RLock()
			routerId := peer.fsm.gConf.Config.RouterId
			peer.fsm.lock.RUnlock()
			if isIBGPPeer {
				if id := path.GetOriginatorID(); routerId == id.String() {
					log.WithFields(log.Fields{
						"Topic":        "Peer",
						"Key":          peer.ID(),
						"OriginatorID": id,
						"Data":         path,
					}).Debug("Originator ID is mine, ignore")
					path.SetRejected(true)
					continue
				}
			}
			paths = append(paths, path)
		}
		peer.adjRibIn.Update(e.PathList)
		peer.fsm.lock.RLock()
		peerAfiSafis := peer.fsm.pConf.AfiSafis
		peer.fsm.lock.RUnlock()
		for _, af := range peerAfiSafis {
			if msg := peer.doPrefixLimit(af.State.Family, &af.PrefixLimit.Config); msg != nil {
				return nil, nil, msg
			}
		}
		return paths, eor, nil
	}
	return nil, nil, nil
}

func (peer *peer) startFSMHandler() {
	peer.fsm.lock.Lock()
	peer.fsm.wg.Add(1)
	go peer.fsm.start(context.TODO(), peer.fsm.wg)
	peer.fsm.lock.Unlock()
}

func (peer *peer) StaleAll(rfList []bgp.RouteFamily) []*table.Path {
	return peer.adjRibIn.StaleAll(rfList)
}

func (peer *peer) PassConn(conn *net.TCPConn) {
	select {
	case peer.fsm.connCh <- conn:
	default:
		conn.Close()
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.ID(),
		}).Warn("accepted conn is closed to avoid be blocked")
	}
}

func (peer *peer) DropAll(rfList []bgp.RouteFamily) []*table.Path {
	return peer.adjRibIn.Drop(rfList)
}

func (s *BgpServer) EnablePeer(ctx context.Context, r *api.EnablePeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.setAdminState(r.Address, "", true)
	}, true)
}

func (s *BgpServer) DisablePeer(ctx context.Context, r *api.DisablePeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.setAdminState(r.Address, r.Communication, false)
	}, true)
}

func (s *BgpServer) ShutdownPeer(ctx context.Context, r *api.ShutdownPeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.sendNotification("Neighbor shutdown", r.Address, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, newAdministrativeCommunication(r.Communication))
	}, true)
}

func (s *BgpServer) ResetPeer(ctx context.Context, r *api.ResetPeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		addr := r.Address
		comm := r.Communication
		if r.Soft {
			var err error
			if addr == "all" {
				addr = ""
			}
			family := bgp.RouteFamily(0)
			switch r.Direction {
			case api.ResetPeerRequest_IN:
				err = s.sResetIn(addr, family)
			case api.ResetPeerRequest_OUT:
				err = s.sResetOut(addr, family)
			case api.ResetPeerRequest_BOTH:
				err = s.sReset(addr, family)
			default:
				err = fmt.Errorf("unknown direction")
			}
			return err
		}

		err := s.sendNotification("Neighbor reset", addr, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, newAdministrativeCommunication(comm))
		if err != nil {
			return err
		}
		peers, _ := s.addrToPeers(addr)
		for _, peer := range peers {
			peer.fsm.lock.Lock()
			peer.fsm.idleHoldTime = peer.fsm.pConf.Timers.Config.IdleHoldTimeAfterReset
			peer.fsm.lock.Unlock()
		}
		return nil
	}, true)
}

func (s *BgpServer) UpdatePeer(ctx context.Context, r *api.UpdatePeerRequest) (rsp *api.UpdatePeerResponse, err error) {
	if r == nil || r.Peer == nil {
		return nil, fmt.Errorf("nil request")
	}
	doSoftReset := false
	err = s.mgmtOperation(func() error {
		c, err := newNeighborFromAPIStruct(r.Peer)
		if err != nil {
			return err
		}
		doSoftReset, err = s.updateNeighbor(c)
		return err
	}, true)
	return &api.UpdatePeerResponse{NeedsSoftResetIn: doSoftReset}, err
}

func (s *BgpServer) addrToPeers(addr string) (l []*peer, err error) {
	if len(addr) == 0 {
		for _, p := range s.neighborMap {
			l = append(l, p)
		}
		return l, nil
	}
	p, found := s.neighborMap[addr]
	if !found {
		return l, fmt.Errorf("neighbor that has %v doesn't exist", addr)
	}
	return []*peer{p}, nil
}

func (s *BgpServer) ListDynamicNeighbor(ctx context.Context, r *api.ListDynamicNeighborRequest, fn func(neighbor *api.DynamicNeighbor)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	toApi := func(dn *config.DynamicNeighbor) *api.DynamicNeighbor {
		return &api.DynamicNeighbor{
			Prefix:    dn.Config.Prefix,
			PeerGroup: dn.Config.PeerGroup,
		}
	}
	var l []*api.DynamicNeighbor
	s.mgmtOperation(func() error {
		peerGroupName := r.PeerGroup
		for k, group := range s.peerGroupMap {
			if peerGroupName != "" && peerGroupName != k {
				continue
			}
			for _, dn := range group.dynamicNeighbors {
				l = append(l, toApi(dn))
			}
		}
		return nil
	}, false)
	for _, dn := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(dn)
		}
	}
	return nil
}

func (s *BgpServer) ListPeerGroup(ctx context.Context, r *api.ListPeerGroupRequest, fn func(*api.PeerGroup)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.PeerGroup
	s.mgmtOperation(func() error {
		peerGroupName := r.PeerGroupName
		l = make([]*api.PeerGroup, 0, len(s.peerGroupMap))
		for k, group := range s.peerGroupMap {
			if peerGroupName != "" && peerGroupName != k {
				continue
			}
			pg := config.NewPeerGroupFromConfigStruct(group.Conf)
			l = append(l, pg)
		}
		return nil
	}, false)
	for _, pg := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(pg)
		}
	}
	return nil
}

func (s *BgpServer) ListPeer(ctx context.Context, r *api.ListPeerRequest, fn func(*api.Peer)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Peer
	s.mgmtOperation(func() error {
		address := r.Address
		getAdvertised := r.EnableAdvertised
		l = make([]*api.Peer, 0, len(s.neighborMap))
		for k, peer := range s.neighborMap {
			peer.fsm.lock.RLock()
			neighborIface := peer.fsm.pConf.Config.NeighborInterface
			peer.fsm.lock.RUnlock()
			if address != "" && address != k && address != neighborIface {
				continue
			}
			// FIXME: should remove toConfig() conversion
			p := config.NewPeerFromConfigStruct(s.toConfig(peer, getAdvertised))
			for _, family := range peer.configuredRFlist() {
				for i, afisafi := range p.AfiSafis {
					if !afisafi.Config.Enabled {
						continue
					}
					afi, safi := bgp.RouteFamilyToAfiSafi(family)
					c := afisafi.Config
					if c.Family != nil && c.Family.Afi == api.Family_Afi(afi) && c.Family.Safi == api.Family_Safi(safi) {
						flist := []bgp.RouteFamily{family}
						received := uint64(peer.adjRibIn.Count(flist))
						accepted := uint64(peer.adjRibIn.Accepted(flist))
						advertised := uint64(0)
						if getAdvertised {
							pathList, _ := s.getBestFromLocal(peer, flist)
							advertised = uint64(len(pathList))
						}
						p.AfiSafis[i].State = &api.AfiSafiState{
							Family:     c.Family,
							Enabled:    true,
							Received:   received,
							Accepted:   accepted,
							Advertised: advertised,
						}
					}
				}
			}
			l = append(l, p)
		}
		return nil
	}, false)
	for _, p := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(p)
		}
	}
	return nil
}

func (s *BgpServer) addPeerGroup(c *config.PeerGroup) error {
	name := c.Config.PeerGroupName
	if _, y := s.peerGroupMap[name]; y {
		return fmt.Errorf("can't overwrite the existing peer-group: %s", name)
	}

	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Name":  name,
	}).Info("Add a peer group configuration")

	s.peerGroupMap[c.Config.PeerGroupName] = newPeerGroup(c)

	return nil
}

func (s *BgpServer) addNeighbor(c *config.Neighbor) error {
	addr, err := c.ExtractNeighborAddress()
	if err != nil {
		return err
	}

	if _, y := s.neighborMap[addr]; y {
		return fmt.Errorf("can't overwrite the existing peer: %s", addr)
	}

	var pgConf *config.PeerGroup
	if c.Config.PeerGroup != "" {
		pg, ok := s.peerGroupMap[c.Config.PeerGroup]
		if !ok {
			return fmt.Errorf("no such peer-group: %s", c.Config.PeerGroup)
		}
		pgConf = pg.Conf
	}

	if err := config.SetDefaultNeighborConfigValues(c, pgConf, &s.bgpConfig.Global); err != nil {
		return err
	}

	if c.RouteServer.Config.RouteServerClient && c.RouteReflector.Config.RouteReflectorClient {
		return fmt.Errorf("can't be both route-server-client and route-reflector-client")
	}

	klog.Infof(fmt.Sprintf("[addNeighbor]Add a peer configuration for addr:%s:%d", addr, c.Transport.Config.RemotePort)) // 127.0.0.1:1791

	rib := s.globalRib
	if c.RouteServer.Config.RouteServerClient {
		rib = s.rsRib
	}
	peer := newPeer(&s.bgpConfig.Global, c, rib, s.policy)
	peer.fsm.incomingCh = s.incomingCh

	s.policy.SetPeerPolicy(peer.ID(), c.ApplyPolicy)
	s.neighborMap[addr] = peer
	if name := c.Config.PeerGroup; name != "" {
		s.peerGroupMap[name].AddMember(*c)
	}
	peer.startFSMHandler()
	s.broadcastPeerState(peer, bgp.BGP_FSM_IDLE, nil)
	return nil
}

func newWatchEventPeerState(peer *peer, m *fsmMsg) *watchEventPeerState {
	var laddr string
	var rport, lport uint16
	if peer.fsm.conn != nil {
		_, rport = peer.fsm.RemoteHostPort()
		laddr, lport = peer.fsm.LocalHostPort()
	}
	sentOpen := buildopen(peer.fsm.gConf, peer.fsm.pConf)
	peer.fsm.lock.RLock()
	recvOpen := peer.fsm.recvOpen
	e := &watchEventPeerState{
		PeerAS:        peer.fsm.peerInfo.AS,
		LocalAS:       peer.fsm.peerInfo.LocalAS,
		PeerAddress:   peer.fsm.peerInfo.Address,
		LocalAddress:  net.ParseIP(laddr),
		PeerPort:      rport,
		LocalPort:     lport,
		PeerID:        peer.fsm.peerInfo.ID,
		SentOpen:      sentOpen,
		RecvOpen:      recvOpen,
		State:         peer.fsm.state,
		AdminState:    peer.fsm.adminState,
		Timestamp:     time.Now(),
		PeerInterface: peer.fsm.pConf.Config.NeighborInterface,
	}
	peer.fsm.lock.RUnlock()

	if m != nil {
		e.StateReason = m.StateReason
	}
	return e
}

func (s *BgpServer) broadcastPeerState(peer *peer, oldState bgp.FSMState, e *fsmMsg) {
	peer.fsm.lock.RLock()
	newState := peer.fsm.state
	peer.fsm.lock.RUnlock()
	if oldState == bgp.BGP_FSM_ESTABLISHED || newState == bgp.BGP_FSM_ESTABLISHED {
		s.notifyWatcher(watchEventTypePeerState, newWatchEventPeerState(peer, e))
	}
}

func (s *BgpServer) AddPeerGroup(ctx context.Context, r *api.AddPeerGroupRequest) error {
	if r == nil || r.PeerGroup == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c, err := newPeerGroupFromAPIStruct(r.PeerGroup)
		if err != nil {
			return err
		}
		return s.addPeerGroup(c)
	}, true)
}

func (s *BgpServer) AddPeer(ctx context.Context, r *api.AddPeerRequest) error {
	if r == nil || r.Peer == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c, err := newNeighborFromAPIStruct(r.Peer)
		if err != nil {
			return err
		}
		return s.addNeighbor(c)
	}, true)
}

func (s *BgpServer) AddDynamicNeighbor(ctx context.Context, r *api.AddDynamicNeighborRequest) error {
	if r == nil || r.DynamicNeighbor == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c := &config.DynamicNeighbor{Config: config.DynamicNeighborConfig{
			Prefix:    r.DynamicNeighbor.Prefix,
			PeerGroup: r.DynamicNeighbor.PeerGroup},
		}
		s.peerGroupMap[c.Config.PeerGroup].AddDynamicNeighbor(c)
		return nil
	}, true)
}

func (s *BgpServer) deletePeerGroup(name string) error {
	if _, y := s.peerGroupMap[name]; !y {
		return fmt.Errorf("can't delete a peer-group %s which does not exist", name)
	}

	log.WithFields(log.Fields{
		"Topic": "Peer",
		"Name":  name,
	}).Info("Delete a peer group configuration")

	delete(s.peerGroupMap, name)
	return nil
}

func (s *BgpServer) deleteNeighbor(c *config.Neighbor, code, subcode uint8) error {
	if c.Config.PeerGroup != "" {
		_, y := s.peerGroupMap[c.Config.PeerGroup]
		if y {
			s.peerGroupMap[c.Config.PeerGroup].DeleteMember(*c)
		}
	}

	addr, err := c.ExtractNeighborAddress()
	if err != nil {
		return err
	}

	n, y := s.neighborMap[addr]
	if !y {
		return fmt.Errorf("can't delete a peer configuration for %s", addr)
	}
	for _, l := range s.listListeners(addr) {
		if err := setTCPMD5SigSockopt(l, addr, ""); err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Warnf("failed to unset md5: %s", err)
		}
	}
	log.WithFields(log.Fields{
		"Topic": "Peer",
	}).Infof("Delete a peer configuration for:%s", addr)

	n.stopPeerRestarting()
	n.fsm.notification <- bgp.NewBGPNotificationMessage(code, subcode, nil)
	//n.fsm.h.ctxCancel()

	delete(s.neighborMap, addr)
	s.propagateUpdate(n, n.DropAll(n.configuredRFlist()))
	return nil
}

func (s *BgpServer) DeletePeerGroup(ctx context.Context, r *api.DeletePeerGroupRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		name := r.Name
		for _, n := range s.neighborMap {
			n.fsm.lock.RLock()
			peerGroup := n.fsm.pConf.Config.PeerGroup
			n.fsm.lock.RUnlock()
			if peerGroup == name {
				return fmt.Errorf("failed to delete peer-group %s: neighbor %s is in use", name, n.ID())
			}
		}
		return s.deletePeerGroup(name)
	}, true)
}

func (s *BgpServer) DeletePeer(ctx context.Context, r *api.DeletePeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c := &config.Neighbor{Config: config.NeighborConfig{
			NeighborAddress:   r.Address,
			NeighborInterface: r.Interface,
		}}
		return s.deleteNeighbor(c, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED)
	}, true)
}

func (s *BgpServer) DeleteDynamicNeighbor(ctx context.Context, r *api.DeleteDynamicNeighborRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		s.peerGroupMap[r.PeerGroup].DeleteDynamicNeighbor(r.Prefix)
		return nil
	}, true)
}

func (s *BgpServer) updatePeerGroup(pg *config.PeerGroup) (needsSoftResetIn bool, err error) {
	name := pg.Config.PeerGroupName

	_, ok := s.peerGroupMap[name]
	if !ok {
		return false, fmt.Errorf("peer-group %s doesn't exist", name)
	}
	s.peerGroupMap[name].Conf = pg

	for _, n := range s.peerGroupMap[name].members {
		c := n
		u, err := s.updateNeighbor(&c)
		if err != nil {
			return needsSoftResetIn, err
		}
		needsSoftResetIn = needsSoftResetIn || u
	}
	return needsSoftResetIn, nil
}

func (s *BgpServer) UpdatePeerGroup(ctx context.Context, r *api.UpdatePeerGroupRequest) (rsp *api.UpdatePeerGroupResponse, err error) {
	if r == nil || r.PeerGroup == nil {
		return nil, fmt.Errorf("nil request")
	}
	doSoftreset := false
	err = s.mgmtOperation(func() error {
		pg, err := newPeerGroupFromAPIStruct(r.PeerGroup)
		if err != nil {
			return err
		}
		doSoftreset, err = s.updatePeerGroup(pg)
		return err
	}, true)
	return &api.UpdatePeerGroupResponse{NeedsSoftResetIn: doSoftreset}, err
}

func (s *BgpServer) updateNeighbor(c *config.Neighbor) (needsSoftResetIn bool, err error) {
	if c.Config.PeerGroup != "" {
		if pg, ok := s.peerGroupMap[c.Config.PeerGroup]; ok {
			if err := config.SetDefaultNeighborConfigValues(c, pg.Conf, &s.bgpConfig.Global); err != nil {
				return needsSoftResetIn, err
			}
		} else {
			return needsSoftResetIn, fmt.Errorf("no such peer-group: %s", c.Config.PeerGroup)
		}
	}

	addr, err := c.ExtractNeighborAddress()
	if err != nil {
		return needsSoftResetIn, err
	}

	peer, ok := s.neighborMap[addr]
	if !ok {
		return needsSoftResetIn, fmt.Errorf("neighbor that has %v doesn't exist", addr)
	}

	if !peer.fsm.pConf.ApplyPolicy.Equal(&c.ApplyPolicy) {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   addr,
		}).Info("Update ApplyPolicy")
		s.policy.SetPeerPolicy(peer.ID(), c.ApplyPolicy)
		peer.fsm.pConf.ApplyPolicy = c.ApplyPolicy
		needsSoftResetIn = true
	}
	original := peer.fsm.pConf

	if !original.AsPathOptions.Config.Equal(&c.AsPathOptions.Config) {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.ID(),
		}).Info("Update aspath options")
		needsSoftResetIn = true
	}

	if original.NeedsResendOpenMessage(c) {
		sub := uint8(bgp.BGP_ERROR_SUB_OTHER_CONFIGURATION_CHANGE)
		if original.Config.AdminDown != c.Config.AdminDown {
			sub = bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN
			state := "Admin Down"

			if !c.Config.AdminDown {
				state = "Admin Up"
			}
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID(),
				"State": state,
			}).Info("Update admin-state configuration")
		} else if original.Config.PeerAs != c.Config.PeerAs {
			sub = bgp.BGP_ERROR_SUB_PEER_DECONFIGURED
		}
		if err = s.deleteNeighbor(peer.fsm.pConf, bgp.BGP_ERROR_CEASE, sub); err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Error(err)
			return needsSoftResetIn, err
		}
		err = s.addNeighbor(c)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Error(err)
		}
		return needsSoftResetIn, err
	}

	if !original.Timers.Config.Equal(&c.Timers.Config) {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   peer.ID(),
		}).Info("Update timer configuration")
		peer.fsm.pConf.Timers.Config = c.Timers.Config
	}

	err = peer.updatePrefixLimitConfig(c.AfiSafis)
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   addr,
		}).Error(err)
		// rollback to original state
		peer.fsm.pConf = original
	}
	return needsSoftResetIn, err
}

func (s *BgpServer) deleteDynamicNeighbor(peer *peer, oldState bgp.FSMState, e *fsmMsg) {
	peer.stopPeerRestarting()
	peer.fsm.lock.RLock()
	delete(s.neighborMap, peer.fsm.pConf.State.NeighborAddress)
	peer.fsm.lock.RUnlock()
	//s.delIncoming(peer.fsm.incomingCh)
	s.broadcastPeerState(peer, oldState, e)
}

func (s *BgpServer) matchLongestDynamicNeighborPrefix(a string) *peerGroup {
	ipAddr := net.ParseIP(a)
	longestMask := net.CIDRMask(0, 32).String()
	var longestPG *peerGroup
	for _, pg := range s.peerGroupMap {
		for _, d := range pg.dynamicNeighbors {
			_, netAddr, _ := net.ParseCIDR(d.Config.Prefix)
			if netAddr.Contains(ipAddr) {
				if netAddr.Mask.String() > longestMask ||
					(netAddr.Mask.String() == longestMask && longestMask == net.CIDRMask(0, 32).String()) {
					longestMask = netAddr.Mask.String()
					longestPG = pg
				}
			}
		}
	}
	return longestPG
}
