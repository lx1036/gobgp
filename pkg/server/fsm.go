// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
	"k8s.io/klog/v2"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	"github.com/osrg/gobgp/pkg/packet/bmp"

	log "github.com/sirupsen/logrus"
)

const (
	minConnectRetryInterval = 5
)

type fsmStateReasonType uint8

const (
	fsmDying fsmStateReasonType = iota
	fsmAdminDown
	fsmReadFailed
	fsmWriteFailed
	fsmNotificationSent
	fsmNotificationRecv
	fsmHoldTimerExpired
	fsmIdleTimerExpired
	fsmRestartTimerExpired
	fsmGracefulRestart
	fsmInvalidMsg
	fsmNewConnection
	fsmOpenMsgReceived
	fsmOpenMsgNegotiated
	fsmHardReset
	fsmDeConfigured
)

type fsmStateReason struct {
	Type            fsmStateReasonType
	BGPNotification *bgp.BGPMessage
	Data            []byte
}

func newfsmStateReason(typ fsmStateReasonType, notif *bgp.BGPMessage, data []byte) *fsmStateReason {
	return &fsmStateReason{
		Type:            typ,
		BGPNotification: notif,
		Data:            data,
	}
}

func (r fsmStateReason) String() string {
	switch r.Type {
	case fsmDying:
		return "dying"
	case fsmAdminDown:
		return "admin-down"
	case fsmReadFailed:
		return "read-failed"
	case fsmWriteFailed:
		return "write-failed"
	case fsmNotificationSent:
		body := r.BGPNotification.Body.(*bgp.BGPNotification)
		return fmt.Sprintf("notification-sent %s", bgp.NewNotificationErrorCode(body.ErrorCode, body.ErrorSubcode).String())
	case fsmNotificationRecv:
		body := r.BGPNotification.Body.(*bgp.BGPNotification)
		return fmt.Sprintf("notification-received %s", bgp.NewNotificationErrorCode(body.ErrorCode, body.ErrorSubcode).String())
	case fsmHoldTimerExpired:
		return "hold-timer-expired"
	case fsmIdleTimerExpired:
		return "idle-hold-timer-expired"
	case fsmRestartTimerExpired:
		return "restart-timer-expired"
	case fsmGracefulRestart:
		return "graceful-restart"
	case fsmInvalidMsg:
		return "invalid-msg"
	case fsmNewConnection:
		return "new-connection"
	case fsmOpenMsgReceived:
		return "open-msg-received"
	case fsmOpenMsgNegotiated:
		return "open-msg-negotiated"
	case fsmHardReset:
		return "hard-reset"
	default:
		return "unknown"
	}
}

type fsmMsgType int

const (
	_ fsmMsgType = iota
	fsmMsgStateChange
	fsmMsgBGPMessage
	fsmMsgRouteRefresh
)

type fsmMsg struct {
	MsgType     fsmMsgType
	fsm         *fsm
	MsgSrc      string
	MsgData     interface{}
	StateReason *fsmStateReason
	PathList    []*table.Path
	timestamp   time.Time
	payload     []byte
}

type fsmOutgoingMsg struct {
	Paths        []*table.Path
	Notification *bgp.BGPMessage
	StayIdle     bool
}

const (
	holdtimeOpensent = 240
	holdtimeIdle     = 5
)

type adminState int

const (
	adminStateUp adminState = iota
	adminStateDown
	adminStatePfxCt
)

func (s adminState) String() string {
	switch s {
	case adminStateUp:
		return "adminStateUp"
	case adminStateDown:
		return "adminStateDown"
	case adminStatePfxCt:
		return "adminStatePfxCt"
	default:
		return "Unknown"
	}
}

type adminStateOperation struct {
	State         adminState
	Communication []byte
}

type fsm struct {
	wg *sync.WaitGroup

	gConf *config.Global
	pConf *config.Neighbor
	lock  sync.RWMutex
	state bgp.FSMState

	outgoingCh chan *fsmOutgoingMsg
	incomingCh chan *fsmMsg

	reason           *fsmStateReason
	conn             net.Conn
	connCh           chan net.Conn
	idleHoldTime     float64
	opensentHoldTime float64
	adminState       adminState
	adminStateCh     chan adminStateOperation
	//h                    *fsmHandler
	rfMap                map[bgp.RouteFamily]bgp.BGPAddPathMode
	capMap               map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface
	recvOpen             *bgp.BGPMessage
	peerInfo             *table.PeerInfo
	gracefulRestartTimer *time.Timer
	twoByteAsTrans       bool
	marshallingOptions   *bgp.MarshallingOption
	notification         chan *bgp.BGPMessage

	// fsm handler
	sentNotification *bgp.BGPMessage
	stateReasonCh    chan fsmStateReason
	holdTimerResetCh chan bool
	msgCh            *channels.InfiniteChannel
}

func newFSM(gConf *config.Global, pConf *config.Neighbor) *fsm {
	adminState := adminStateUp
	if pConf.Config.AdminDown {
		adminState = adminStateDown
	}
	pConf.State.SessionState = config.IntToSessionStateMap[int(bgp.BGP_FSM_IDLE)]
	pConf.Timers.State.Downtime = time.Now().Unix()
	fsm := &fsm{
		wg: &sync.WaitGroup{},

		outgoingCh: make(chan *fsmOutgoingMsg, 1024),
		//incomingCh: make(chan *fsmMsg, 1024), // 不要这里实例化，在 server 上层实例化

		gConf:                gConf,
		pConf:                pConf,
		state:                bgp.BGP_FSM_IDLE,
		connCh:               make(chan net.Conn, 1),
		opensentHoldTime:     float64(holdtimeOpensent),
		adminState:           adminState,
		adminStateCh:         make(chan adminStateOperation, 1),
		rfMap:                make(map[bgp.RouteFamily]bgp.BGPAddPathMode),
		capMap:               make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface),
		peerInfo:             table.NewPeerInfo(gConf, pConf),
		gracefulRestartTimer: time.NewTimer(time.Hour),

		// fsm handler
		notification:     make(chan *bgp.BGPMessage, 1),
		stateReasonCh:    make(chan fsmStateReason, 2),
		holdTimerResetCh: make(chan bool, 2),
	}
	fsm.gracefulRestartTimer.Stop()
	return fsm
}

func (fsm *fsm) start(ctx context.Context, wg *sync.WaitGroup) error {
	defer wg.Done()

	fsm.lock.RLock()
	oldState := fsm.state
	fsm.lock.RUnlock()

	var reason *fsmStateReason
	nextState := bgp.FSMState(-1)
	fsm.lock.RLock()
	fsmState := fsm.state
	fsm.lock.RUnlock()

	switch fsmState {
	case bgp.BGP_FSM_IDLE:
		nextState, reason = fsm.idle(ctx)
		// case bgp.BGP_FSM_CONNECT:
		// 	nextState = fsm.connect()
	case bgp.BGP_FSM_ACTIVE:
		nextState, reason = fsm.active(ctx)
	case bgp.BGP_FSM_OPENSENT:
		nextState, reason = fsm.opensent(ctx)
	case bgp.BGP_FSM_OPENCONFIRM:
		nextState, reason = fsm.openconfirm(ctx)
	case bgp.BGP_FSM_ESTABLISHED:
		nextState, reason = fsm.established(ctx)
	}

	fsm.lock.RLock()
	fsm.reason = reason

	if nextState == bgp.BGP_FSM_ESTABLISHED && oldState == bgp.BGP_FSM_OPENCONFIRM {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   fsm.pConf.State.NeighborAddress,
			"State": fsm.state.String(),
		}).Info("Peer Up")
	}

	if oldState == bgp.BGP_FSM_ESTABLISHED {
		// The main goroutine sent the notification due to
		// deconfiguration or something.
		reason := fsm.reason
		if fsm.sentNotification != nil {
			reason.Type = fsmNotificationSent
			reason.BGPNotification = fsm.sentNotification
		}
		log.WithFields(log.Fields{
			"Topic":  "Peer",
			"Key":    fsm.pConf.State.NeighborAddress,
			"State":  fsm.state.String(),
			"Reason": reason.String(),
		}).Info("Peer Down")
	}
	fsm.lock.RUnlock()

	fsm.lock.RLock()
	fsm.incomingCh <- &fsmMsg{
		fsm:         fsm,
		MsgType:     fsmMsgStateChange,
		MsgSrc:      fsm.pConf.State.NeighborAddress,
		MsgData:     nextState,
		StateReason: reason,
	}
	fsm.lock.RUnlock()
	return nil
}

func (fsm *fsm) idle(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	fsm.lock.RLock()
	idleHoldTimer := time.NewTimer(time.Second * time.Duration(fsm.idleHoldTime))
	fsm.lock.RUnlock()

	for {
		select {
		case <-ctx.Done():
			return -1, newfsmStateReason(fsmDying, nil, nil)
		case <-fsm.gracefulRestartTimer.C:
			fsm.lock.RLock()
			restarting := fsm.pConf.GracefulRestart.State.PeerRestarting
			fsm.lock.RUnlock()

			if restarting {
				fsm.lock.RLock()
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
				}).Warn("graceful restart timer expired")
				fsm.lock.RUnlock()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmRestartTimerExpired, nil, nil)
			}
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
			}).Warn("Closed an accepted connection")
			fsm.lock.RUnlock()

		case <-idleHoldTimer.C:
			fsm.lock.RLock()
			adminStateUp := fsm.adminState == adminStateUp
			fsm.lock.RUnlock()

			if adminStateUp {
				fsm.lock.Lock()
				log.WithFields(log.Fields{
					"Topic":    "Peer",
					"Key":      fsm.pConf.State.NeighborAddress,
					"Duration": fsm.idleHoldTime,
				}).Debug("IdleHoldTimer expired")
				fsm.idleHoldTime = holdtimeIdle
				fsm.lock.Unlock()
				return bgp.BGP_FSM_ACTIVE, newfsmStateReason(fsmIdleTimerExpired, nil, nil)

			} else {
				log.WithFields(log.Fields{"Topic": "Peer"}).Debug("IdleHoldTimer expired, but stay at idle because the admin state is DOWN")
			}

		case stateOp := <-fsm.adminStateCh:
			err := fsm.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					// stop idle hold timer
					idleHoldTimer.Stop()

				case adminStateUp:
					// restart idle hold timer
					fsm.lock.RLock()
					idleHoldTimer.Reset(time.Second * time.Duration(fsm.idleHoldTime))
					fsm.lock.RUnlock()
				}
			}
		}
	}
}

func (fsm *fsm) opensent(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	fsm.lock.RLock()
	m := buildopen(fsm.gConf, fsm.pConf)
	fsm.lock.RUnlock()

	b, _ := m.Serialize()
	fsm.conn.Write(b)
	fsm.bgpMessageStateUpdate(m.Header.Type, false)

	fsm.msgCh = channels.NewInfiniteChannel()

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go fsm.recvMessage(ctx, &wg)

	// RFC 4271 P.60
	// sets its HoldTimer to a large value
	// A HoldTimer value of 4 minutes is suggested as a "large value"
	// for the HoldTimer
	fsm.lock.RLock()
	holdTimer := time.NewTimer(time.Second * time.Duration(fsm.opensentHoldTime))
	fsm.lock.RUnlock()

	for {
		select {
		case <-ctx.Done():
			fsm.conn.Close()
			return -1, newfsmStateReason(fsmDying, nil, nil)
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
			}).Warn("Closed an accepted connection")
			fsm.lock.RUnlock()
		case <-fsm.gracefulRestartTimer.C:
			fsm.lock.RLock()
			restarting := fsm.pConf.GracefulRestart.State.PeerRestarting
			fsm.lock.RUnlock()
			if restarting {
				fsm.lock.RLock()
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
				}).Warn("graceful restart timer expired")
				fsm.lock.RUnlock()
				fsm.conn.Close()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmRestartTimerExpired, nil, nil)
			}
		case i, ok := <-fsm.msgCh.Out():
			if !ok {
				continue
			}
			e := i.(*fsmMsg)
			switch m := e.MsgData.(type) {
			case *bgp.BGPMessage:
				if m.Header.Type == bgp.BGP_MSG_OPEN {
					fsm.lock.Lock()
					fsm.recvOpen = m
					fsm.lock.Unlock()

					body := m.Body.(*bgp.BGPOpen)

					fsm.lock.RLock()
					fsmPeerAS := fsm.pConf.Config.PeerAs
					fsm.lock.RUnlock()
					peerAs, err := bgp.ValidateOpenMsg(body, fsmPeerAS, fsm.peerInfo.LocalAS, net.ParseIP(fsm.gConf.Config.RouterId))
					if err != nil {
						m, _ := fsm.sendNotificationFromErrorMsg(err.(*bgp.MessageError))
						return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, m, nil)
					}

					// ASN negotiation was skipped
					fsm.lock.RLock()
					asnNegotiationSkipped := fsm.pConf.Config.PeerAs == 0
					fsm.lock.RUnlock()
					if asnNegotiationSkipped {
						fsm.lock.Lock()
						typ := config.PEER_TYPE_EXTERNAL
						if fsm.peerInfo.LocalAS == peerAs {
							typ = config.PEER_TYPE_INTERNAL
						}
						fsm.pConf.State.PeerType = typ
						log.WithFields(log.Fields{
							"Topic": "Peer",
							"Key":   fsm.pConf.State.NeighborAddress,
							"State": fsm.state.String(),
						}).Infof("skipped asn negotiation: peer-as: %d, peer-type: %s", peerAs, typ)
						fsm.lock.Unlock()
					} else {
						fsm.lock.Lock()
						fsm.pConf.State.PeerType = fsm.pConf.Config.PeerType
						fsm.lock.Unlock()
					}
					fsm.lock.Lock()
					fsm.pConf.State.PeerAs = peerAs
					fsm.peerInfo.AS = peerAs
					fsm.peerInfo.ID = body.ID
					fsm.capMap, fsm.rfMap = open2Cap(body, fsm.pConf)

					if _, y := fsm.capMap[bgp.BGP_CAP_ADD_PATH]; y {
						fsm.marshallingOptions = &bgp.MarshallingOption{
							AddPath: fsm.rfMap,
						}
					} else {
						fsm.marshallingOptions = nil
					}

					// calculate HoldTime
					// RFC 4271 P.13
					// a BGP speaker MUST calculate the value of the Hold Timer
					// by using the smaller of its configured Hold Time and the Hold Time
					// received in the OPEN message.
					holdTime := float64(body.HoldTime)
					myHoldTime := fsm.pConf.Timers.Config.HoldTime
					if holdTime > myHoldTime {
						fsm.pConf.Timers.State.NegotiatedHoldTime = myHoldTime
					} else {
						fsm.pConf.Timers.State.NegotiatedHoldTime = holdTime
					}

					keepalive := fsm.pConf.Timers.Config.KeepaliveInterval
					if n := fsm.pConf.Timers.State.NegotiatedHoldTime; n < myHoldTime {
						keepalive = n / 3
					}
					fsm.pConf.Timers.State.KeepaliveInterval = keepalive

					gr, ok := fsm.capMap[bgp.BGP_CAP_GRACEFUL_RESTART]
					if fsm.pConf.GracefulRestart.Config.Enabled && ok {
						state := &fsm.pConf.GracefulRestart.State
						state.Enabled = true
						cap := gr[len(gr)-1].(*bgp.CapGracefulRestart)
						state.PeerRestartTime = uint16(cap.Time)

						for _, t := range cap.Tuples {
							n := bgp.AddressFamilyNameMap[bgp.AfiSafiToRouteFamily(t.AFI, t.SAFI)]
							for i, a := range fsm.pConf.AfiSafis {
								if string(a.Config.AfiSafiName) == n {
									fsm.pConf.AfiSafis[i].MpGracefulRestart.State.Enabled = true
									fsm.pConf.AfiSafis[i].MpGracefulRestart.State.Received = true
									break
								}
							}
						}

						// RFC 4724 4.1
						// To re-establish the session with its peer, the Restarting Speaker
						// MUST set the "Restart State" bit in the Graceful Restart Capability
						// of the OPEN message.
						if fsm.pConf.GracefulRestart.State.PeerRestarting && cap.Flags&0x08 == 0 {
							log.WithFields(log.Fields{
								"Topic": "Peer",
								"Key":   fsm.pConf.State.NeighborAddress,
								"State": fsm.state.String(),
							}).Warn("restart flag is not set")
							// just ignore
						}

						// RFC 4724 3
						// The most significant bit is defined as the Restart State (R)
						// bit, ...(snip)... When set (value 1), this bit
						// indicates that the BGP speaker has restarted, and its peer MUST
						// NOT wait for the End-of-RIB marker from the speaker before
						// advertising routing information to the speaker.
						if fsm.pConf.GracefulRestart.State.LocalRestarting && cap.Flags&0x08 != 0 {
							log.WithFields(log.Fields{
								"Topic": "Peer",
								"Key":   fsm.pConf.State.NeighborAddress,
								"State": fsm.state.String(),
							}).Debug("peer has restarted, skipping wait for EOR")
							for i := range fsm.pConf.AfiSafis {
								fsm.pConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = true
							}
						}
						if fsm.pConf.GracefulRestart.Config.NotificationEnabled && cap.Flags&0x04 > 0 {
							fsm.pConf.GracefulRestart.State.NotificationEnabled = true
						}
					}
					llgr, ok2 := fsm.capMap[bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART]
					if fsm.pConf.GracefulRestart.Config.LongLivedEnabled && ok && ok2 {
						fsm.pConf.GracefulRestart.State.LongLivedEnabled = true
						cap := llgr[len(llgr)-1].(*bgp.CapLongLivedGracefulRestart)
						for _, t := range cap.Tuples {
							n := bgp.AddressFamilyNameMap[bgp.AfiSafiToRouteFamily(t.AFI, t.SAFI)]
							for i, a := range fsm.pConf.AfiSafis {
								if string(a.Config.AfiSafiName) == n {
									fsm.pConf.AfiSafis[i].LongLivedGracefulRestart.State.Enabled = true
									fsm.pConf.AfiSafis[i].LongLivedGracefulRestart.State.Received = true
									fsm.pConf.AfiSafis[i].LongLivedGracefulRestart.State.PeerRestartTime = t.RestartTime
									break
								}
							}
						}
					}

					fsm.lock.Unlock()
					msg := bgp.NewBGPKeepAliveMessage()
					b, _ := msg.Serialize()
					fsm.conn.Write(b)
					fsm.bgpMessageStateUpdate(msg.Header.Type, false)
					return bgp.BGP_FSM_OPENCONFIRM, newfsmStateReason(fsmOpenMsgReceived, nil, nil)
				} else {
					// send notification?
					fsm.conn.Close()
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, nil, nil)
				}
			case *bgp.MessageError:
				msg, _ := fsm.sendNotificationFromErrorMsg(m)
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, msg, nil)
			default:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
					"Data":  e.MsgData,
				}).Panic("unknown msg type")
			}
		case err := <-fsm.stateReasonCh:
			fsm.conn.Close()
			return bgp.BGP_FSM_IDLE, &err
		case <-holdTimer.C:
			m, _ := fsm.sendNotification(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil, "hold timer expired")
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmHoldTimerExpired, m, nil)
		case stateOp := <-fsm.adminStateCh:
			err := fsm.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					fsm.conn.Close()
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminDown, m, nil)
				case adminStateUp:
					log.WithFields(log.Fields{
						"Topic":      "Peer",
						"Key":        fsm.pConf.State.NeighborAddress,
						"State":      fsm.state.String(),
						"adminState": stateOp.State.String(),
					}).Panic("code logic bug")
				}
			}
		}
	}
}

func (fsm *fsm) openconfirm(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	ticker := keepaliveTicker(fsm)
	fsm.msgCh = channels.NewInfiniteChannel()
	fsm.lock.RLock()

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	go fsm.recvMessage(ctx, &wg)

	var holdTimer *time.Timer
	if fsm.pConf.Timers.State.NegotiatedHoldTime == 0 {
		holdTimer = &time.Timer{}
	} else {
		// RFC 4271 P.65
		// sets the HoldTimer according to the negotiated value
		holdTimer = time.NewTimer(time.Second * time.Duration(fsm.pConf.Timers.State.NegotiatedHoldTime))
	}
	fsm.lock.RUnlock()

	for {
		select {
		case <-ctx.Done():
			fsm.conn.Close()
			return -1, newfsmStateReason(fsmDying, nil, nil)
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
			}).Warn("Closed an accepted connection")
			fsm.lock.RUnlock()
		case <-fsm.gracefulRestartTimer.C:
			fsm.lock.RLock()
			restarting := fsm.pConf.GracefulRestart.State.PeerRestarting
			fsm.lock.RUnlock()
			if restarting {
				fsm.lock.RLock()
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
				}).Warn("graceful restart timer expired")
				fsm.lock.RUnlock()
				fsm.conn.Close()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmRestartTimerExpired, nil, nil)
			}
		case <-ticker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			// TODO: check error
			fsm.conn.Write(b)
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
		case i, ok := <-fsm.msgCh.Out():
			if !ok {
				continue
			}
			e := i.(*fsmMsg)
			switch m := e.MsgData.(type) {
			case *bgp.BGPMessage:
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					return bgp.BGP_FSM_ESTABLISHED, newfsmStateReason(fsmOpenMsgNegotiated, nil, nil)
				}
				// send notification ?
				fsm.conn.Close()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, nil, nil)
			case *bgp.MessageError:
				msg, _ := fsm.sendNotificationFromErrorMsg(m)
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, msg, nil)
			default:
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
					"Data":  e.MsgData,
				}).Panic("unknown msg type")
			}
		case err := <-fsm.stateReasonCh:
			fsm.conn.Close()
			return bgp.BGP_FSM_IDLE, &err
		case <-holdTimer.C:
			m, _ := fsm.sendNotification(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil, "hold timer expired")
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmHoldTimerExpired, m, nil)
		case stateOp := <-fsm.adminStateCh:
			err := fsm.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					fsm.conn.Close()
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminDown, nil, nil)
				case adminStateUp:
					log.WithFields(log.Fields{
						"Topic":      "Peer",
						"Key":        fsm.pConf.State.NeighborAddress,
						"State":      fsm.state.String(),
						"adminState": stateOp.State.String(),
					}).Panic("code logic bug")
				}
			}
		}
	}
}

func (fsm *fsm) active(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	c, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup

	fsm.lock.RLock()
	tryConnect := !fsm.pConf.Transport.Config.PassiveMode
	fsm.lock.RUnlock()
	if tryConnect {
		wg.Add(1)
		go fsm.connectLoop(c, &wg)
	}

	defer func() {
		cancel()
		wg.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return -1, newfsmStateReason(fsmDying, nil, nil)
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			fsm.lock.Lock()
			fsm.conn = conn
			fsm.lock.Unlock()
			ttl := 0
			ttlMin := 0

			fsm.lock.RLock()
			if fsm.pConf.TtlSecurity.Config.Enabled {
				ttl = 255
				ttlMin = int(fsm.pConf.TtlSecurity.Config.TtlMin)
			} else if fsm.pConf.Config.PeerAs != 0 && fsm.pConf.Config.PeerType == config.PEER_TYPE_EXTERNAL {
				if fsm.pConf.EbgpMultihop.Config.Enabled {
					ttl = int(fsm.pConf.EbgpMultihop.Config.MultihopTtl)
				} else if fsm.pConf.Transport.Config.Ttl != 0 {
					ttl = int(fsm.pConf.Transport.Config.Ttl)
				} else {
					ttl = 1
				}
			} else if fsm.pConf.Transport.Config.Ttl != 0 {
				ttl = int(fsm.pConf.Transport.Config.Ttl)
			}
			if ttl != 0 {
				if err := setTCPTTLSockopt(conn.(*net.TCPConn), ttl); err != nil {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   fsm.pConf.Config.NeighborAddress,
						"State": fsm.state.String(),
					}).Warnf("cannot set TTL(=%d) for peer: %s", ttl, err)
				}
			}
			if ttlMin != 0 {
				if err := setTCPMinTTLSockopt(conn.(*net.TCPConn), ttlMin); err != nil {
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   fsm.pConf.Config.NeighborAddress,
						"State": fsm.state.String(),
					}).Warnf("cannot set minimal TTL(=%d) for peer: %s", ttl, err)
				}
			}
			fsm.lock.RUnlock()
			// we don't implement delayed open timer so move to opensent right
			// away.
			return bgp.BGP_FSM_OPENSENT, newfsmStateReason(fsmNewConnection, nil, nil)
		case <-fsm.gracefulRestartTimer.C:
			fsm.lock.RLock()
			restarting := fsm.pConf.GracefulRestart.State.PeerRestarting
			fsm.lock.RUnlock()
			if restarting {
				fsm.lock.RLock()
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
				}).Warn("graceful restart timer expired")
				fsm.lock.RUnlock()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmRestartTimerExpired, nil, nil)
			}
		case err := <-fsm.stateReasonCh:
			return bgp.BGP_FSM_IDLE, &err
		case stateOp := <-fsm.adminStateCh:
			err := fsm.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminDown, nil, nil)
				case adminStateUp:
					log.WithFields(log.Fields{
						"Topic":      "Peer",
						"Key":        fsm.pConf.State.NeighborAddress,
						"State":      fsm.state.String(),
						"adminState": stateOp.State.String(),
					}).Panic("code logic bug")
				}
			}
		}
	}
}

func (fsm *fsm) connectLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	retry, addr, port, password, ttl, ttlMin, localAddress, bindInterface := func() (int, string, int, string, uint8, uint8, string, string) {
		fsm.lock.RLock()
		defer fsm.lock.RUnlock()

		tick := int(fsm.pConf.Timers.Config.ConnectRetry)
		if tick < minConnectRetryInterval {
			tick = minConnectRetryInterval
		}

		addr := fsm.pConf.State.NeighborAddress
		port := int(bgp.BGP_PORT)
		if fsm.pConf.Transport.Config.RemotePort != 0 {
			port = int(fsm.pConf.Transport.Config.RemotePort)
		}
		password := fsm.pConf.Config.AuthPassword
		ttl := uint8(0)
		ttlMin := uint8(0)

		if fsm.pConf.TtlSecurity.Config.Enabled {
			ttl = 255
			ttlMin = fsm.pConf.TtlSecurity.Config.TtlMin
		} else if fsm.pConf.Config.PeerAs != 0 && fsm.pConf.Config.PeerType == config.PEER_TYPE_EXTERNAL {
			ttl = 1
			if fsm.pConf.EbgpMultihop.Config.Enabled {
				ttl = fsm.pConf.EbgpMultihop.Config.MultihopTtl
			}
		}
		return tick, addr, port, password, ttl, ttlMin, fsm.pConf.Transport.Config.LocalAddress, fsm.pConf.Transport.Config.BindInterface
	}()

	tick := minConnectRetryInterval
	for {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		timer := time.NewTimer(time.Duration(r.Intn(tick)+tick) * time.Second)
		select {
		case <-ctx.Done():
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Debug("stop connect loop")
			timer.Stop()
			return
		case <-timer.C:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Debug("try to connect")
		}

		laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(localAddress, "0"))
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   addr,
			}).Warnf("failed to resolve local address: %s", err)
		}

		if err == nil {
			d := net.Dialer{
				LocalAddr: laddr,
				Timeout:   time.Duration(tick-1) * time.Second,
				Control: func(network, address string, c syscall.RawConn) error {
					return dialerControl(network, address, c, ttl, ttlMin, password, bindInterface)
				},
			}

			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
			select {
			case <-ctx.Done():
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				}).Debug("stop connect loop")
				return
			default:
			}

			if err == nil {
				select {
				case fsm.connCh <- conn:
					return
				default:
					conn.Close()
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   addr,
					}).Warn("active conn is closed to avoid being blocked")
				}
			} else {
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   addr,
				}).Debugf("failed to connect: %s", err)
			}
		}
		tick = retry
	}
}

func (fsm *fsm) established(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	var wg sync.WaitGroup
	fsm.lock.Lock()
	fsm.conn = fsm.conn
	fsm.lock.Unlock()

	defer wg.Wait()
	wg.Add(2)

	go fsm.sendMessageloop(ctx, &wg)
	//fsm.msgCh = fsm.incomingCh
	go fsm.recvMessageloop(ctx, &wg)

	var holdTimer *time.Timer
	if fsm.pConf.Timers.State.NegotiatedHoldTime == 0 {
		holdTimer = &time.Timer{}
	} else {
		fsm.lock.RLock()
		holdTimer = time.NewTimer(time.Second * time.Duration(fsm.pConf.Timers.State.NegotiatedHoldTime))
		fsm.lock.RUnlock()
	}

	fsm.gracefulRestartTimer.Stop()

	for {
		select {
		case <-ctx.Done():
			select {
			case m := <-fsm.notification:
				b, _ := m.Serialize(fsm.marshallingOptions)
				fsm.conn.Write(b)
			default:
				// nothing to do
			}
			fsm.conn.Close()
			return -1, newfsmStateReason(fsmDying, nil, nil)
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
			}).Warn("Closed an accepted connection")
			fsm.lock.RUnlock()
		case err := <-fsm.stateReasonCh:
			fsm.conn.Close()
			// if recv goroutine hit an error and sent to
			// stateReasonCh, then tx goroutine might take
			// long until it exits because it waits for
			// ctx.Done() or keepalive timer. So let kill
			// it now.
			//fsm.outgoingCh.In() <- err
			fsm.lock.RLock()
			if s := fsm.pConf.GracefulRestart.State; s.Enabled {
				if (s.NotificationEnabled && err.Type == fsmNotificationRecv) ||
					(err.Type == fsmNotificationSent &&
						err.BGPNotification.Body.(*bgp.BGPNotification).ErrorCode == bgp.BGP_ERROR_HOLD_TIMER_EXPIRED) ||
					err.Type == fsmReadFailed ||
					err.Type == fsmWriteFailed {
					err = *newfsmStateReason(fsmGracefulRestart, nil, nil)
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   fsm.pConf.State.NeighborAddress,
						"State": fsm.state.String(),
					}).Info("peer graceful restart")
					fsm.gracefulRestartTimer.Reset(time.Duration(fsm.pConf.GracefulRestart.State.PeerRestartTime) * time.Second)
				}
			}
			fsm.lock.RUnlock()
			return bgp.BGP_FSM_IDLE, &err
		case <-holdTimer.C:
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
			}).Warn("hold timer expired")
			fsm.lock.RUnlock()
			m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
			fsm.outgoingCh <- &fsmOutgoingMsg{Notification: m}
			fsm.lock.RLock()
			s := fsm.pConf.GracefulRestart.State
			fsm.lock.RUnlock()
			// Do not return hold timer expired to server if graceful restart is enabled
			// Let it fallback to read/write error or fsmNotificationSent handled above
			// Reference: https://github.com/osrg/gobgp/issues/2174
			if !s.Enabled {
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmHoldTimerExpired, m, nil)
			}
		case <-fsm.holdTimerResetCh:
			fsm.lock.RLock()
			if fsm.pConf.Timers.State.NegotiatedHoldTime != 0 {
				holdTimer.Reset(time.Second * time.Duration(fsm.pConf.Timers.State.NegotiatedHoldTime))
			}
			fsm.lock.RUnlock()
		case stateOp := <-fsm.adminStateCh:
			err := fsm.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, stateOp.Communication)
					fsm.outgoingCh <- &fsmOutgoingMsg{Notification: m}
				}
			}
		}
	}
}

func (fsm *fsm) sendMessageloop(ctx context.Context, wg *sync.WaitGroup) error {
	sendToStateReasonCh := func(typ fsmStateReasonType, notif *bgp.BGPMessage) {
		// probably doesn't happen but be cautious
		select {
		case fsm.stateReasonCh <- *newfsmStateReason(typ, notif, nil):
		default:
		}
	}

	defer wg.Done()
	conn := fsm.conn
	ticker := keepaliveTicker(fsm)
	send := func(m *bgp.BGPMessage) error {
		fsm.lock.RLock()
		if fsm.twoByteAsTrans && m.Header.Type == bgp.BGP_MSG_UPDATE {
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
				"Data":  m,
			}).Debug("update for 2byte AS peer")
			table.UpdatePathAttrs2ByteAs(m.Body.(*bgp.BGPUpdate))
			table.UpdatePathAggregator2ByteAs(m.Body.(*bgp.BGPUpdate))
		}
		b, err := m.Serialize(fsm.marshallingOptions)
		fsm.lock.RUnlock()
		if err != nil {
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
				"Data":  err,
			}).Warn("failed to serialize")
			fsm.lock.RUnlock()
			fsm.bgpMessageStateUpdate(0, false)
			return nil
		}
		fsm.lock.RLock()
		err = conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(fsm.pConf.Timers.State.NegotiatedHoldTime)))
		fsm.lock.RUnlock()
		if err != nil {
			sendToStateReasonCh(fsmWriteFailed, nil)
			conn.Close()
			return fmt.Errorf("failed to set write deadline")
		}
		_, err = conn.Write(b)
		if err != nil {
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
				"Data":  err,
			}).Warn("failed to send")
			fsm.lock.RUnlock()
			sendToStateReasonCh(fsmWriteFailed, nil)
			conn.Close()
			return fmt.Errorf("closed")
		}
		fsm.bgpMessageStateUpdate(m.Header.Type, false)

		switch m.Header.Type {
		case bgp.BGP_MSG_NOTIFICATION:
			body := m.Body.(*bgp.BGPNotification)
			if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
				communication, rest := decodeAdministrativeCommunication(body.Data)
				fsm.lock.RLock()
				log.WithFields(log.Fields{
					"Topic":               "Peer",
					"Key":                 fsm.pConf.State.NeighborAddress,
					"State":               fsm.state.String(),
					"Code":                body.ErrorCode,
					"Subcode":             body.ErrorSubcode,
					"Communicated-Reason": communication,
					"Data":                rest,
				}).Warn("sent notification")
				fsm.lock.RUnlock()
			} else {
				fsm.lock.RLock()
				log.WithFields(log.Fields{
					"Topic":   "Peer",
					"Key":     fsm.pConf.State.NeighborAddress,
					"State":   fsm.state.String(),
					"Code":    body.ErrorCode,
					"Subcode": body.ErrorSubcode,
					"Data":    body.Data,
				}).Warn("sent notification")
				fsm.lock.RUnlock()
			}
			sendToStateReasonCh(fsmNotificationSent, m)
			conn.Close()
			return fmt.Errorf("closed")
		case bgp.BGP_MSG_UPDATE:
			update := m.Body.(*bgp.BGPUpdate)
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic":       "Peer",
				"Key":         fsm.pConf.State.NeighborAddress,
				"State":       fsm.state.String(),
				"nlri":        update.NLRI,
				"withdrawals": update.WithdrawnRoutes,
				"attributes":  update.PathAttributes,
			}).Debug("sent update")
			fsm.lock.RUnlock()
		default:
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
				"data":  m,
			}).Debug("sent")
			fsm.lock.RUnlock()
		}
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case m := <-fsm.outgoingCh:
			fsm.lock.RLock()
			options := fsm.marshallingOptions
			fsm.lock.RUnlock()
			for _, msg := range table.CreateUpdateMsgFromPaths(m.Paths, options) {
				if err := send(msg); err != nil {
					return nil
				}
			}
			if m.Notification != nil {
				if m.StayIdle {
					// current user is only prefix-limit
					// fix me if this is not the case
					fsm.changeadminState(adminStatePfxCt)
				}
				if err := send(m.Notification); err != nil {
					return nil
				}
			}
		case <-ticker.C:
			if err := send(bgp.NewBGPKeepAliveMessage()); err != nil {
				return nil
			}
		}
	}
}

func (fsm *fsm) recvMessageloop(ctx context.Context, wg *sync.WaitGroup) error {
	defer wg.Done()
	for {
		fmsg, err := fsm.recvMessageWithError()
		if fmsg != nil {
			fsm.incomingCh <- fmsg
		}
		if err != nil {
			return nil
		}
	}
}

func (fsm *fsm) bgpMessageStateUpdate(MessageType uint8, isIn bool) {
	fsm.lock.Lock()
	defer fsm.lock.Unlock()
	state := &fsm.pConf.State.Messages
	timer := &fsm.pConf.Timers
	if isIn {
		state.Received.Total++
	} else {
		state.Sent.Total++
	}
	switch MessageType {
	case bgp.BGP_MSG_OPEN:
		if isIn {
			state.Received.Open++
		} else {
			state.Sent.Open++
		}
	case bgp.BGP_MSG_UPDATE:
		if isIn {
			state.Received.Update++
			timer.State.UpdateRecvTime = time.Now().Unix()
		} else {
			state.Sent.Update++
		}
	case bgp.BGP_MSG_NOTIFICATION:
		if isIn {
			state.Received.Notification++
		} else {
			state.Sent.Notification++
		}
	case bgp.BGP_MSG_KEEPALIVE:
		if isIn {
			state.Received.Keepalive++
		} else {
			state.Sent.Keepalive++
		}
	case bgp.BGP_MSG_ROUTE_REFRESH:
		if isIn {
			state.Received.Refresh++
		} else {
			state.Sent.Refresh++
		}
	default:
		if isIn {
			state.Received.Discarded++
		} else {
			state.Sent.Discarded++
		}
	}
}

func (fsm *fsm) bmpStatsUpdate(statType uint16, increment int) {
	fsm.lock.Lock()
	defer fsm.lock.Unlock()
	stats := &fsm.pConf.State.Messages.Received
	switch statType {
	// TODO
	// Support other stat types.
	case bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE:
		stats.WithdrawUpdate += uint32(increment)
	case bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX:
		stats.WithdrawPrefix += uint32(increment)
	}
}

func (fsm *fsm) StateChange(nextState bgp.FSMState) {
	fsm.lock.Lock()
	defer fsm.lock.Unlock()

	klog.Infof(fmt.Sprintf("[StateChange]state changed, key:%s, old:%s, new:%s, reason:%s",
		fsm.pConf.State.NeighborAddress, fsm.state.String(), nextState.String(), fsm.reason))
	fsm.state = nextState
	switch nextState {
	case bgp.BGP_FSM_ESTABLISHED:
		fsm.pConf.Timers.State.Uptime = time.Now().Unix()
		fsm.pConf.State.EstablishedCount++
		// reset the state set by the previous session
		fsm.twoByteAsTrans = false
		if _, y := fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]; !y {
			fsm.twoByteAsTrans = true
			break
		}
		y := func() bool {
			for _, c := range capabilitiesFromConfig(fsm.pConf) {
				switch c.(type) {
				case *bgp.CapFourOctetASNumber:
					return true
				}
			}
			return false
		}()
		if !y {
			fsm.twoByteAsTrans = true
		}
	default:
		fsm.pConf.Timers.State.Downtime = time.Now().Unix()
	}
}

func (fsm *fsm) RemoteHostPort() (string, uint16) {
	return hostport(fsm.conn.RemoteAddr())

}

func (fsm *fsm) LocalHostPort() (string, uint16) {
	return hostport(fsm.conn.LocalAddr())
}

func (fsm *fsm) sendNotificationFromErrorMsg(e *bgp.MessageError) (*bgp.BGPMessage, error) {
	fsm.lock.RLock()
	established := fsm.conn != nil
	fsm.lock.RUnlock()

	if established {
		m := bgp.NewBGPNotificationMessage(e.TypeCode, e.SubTypeCode, e.Data)
		b, _ := m.Serialize()
		_, err := fsm.conn.Write(b)
		if err == nil {
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
			fsm.sentNotification = m
		}
		fsm.conn.Close()
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   fsm.pConf.State.NeighborAddress,
			"Data":  e,
		}).Warn("sent notification")
		return m, nil
	}
	return nil, fmt.Errorf("can't send notification to %s since TCP connection is not established", fsm.pConf.State.NeighborAddress)
}

func (fsm *fsm) sendNotification(code, subType uint8, data []byte, msg string) (*bgp.BGPMessage, error) {
	e := bgp.NewMessageError(code, subType, data, msg)
	return fsm.sendNotificationFromErrorMsg(e.(*bgp.MessageError))
}

func (fsm *fsm) afiSafiDisable(rf bgp.RouteFamily) string {
	fsm.lock.Lock()
	defer fsm.lock.Unlock()

	n := bgp.AddressFamilyNameMap[rf]

	for i, a := range fsm.pConf.AfiSafis {
		if string(a.Config.AfiSafiName) == n {
			fsm.pConf.AfiSafis[i].State.Enabled = false
			break
		}
	}
	newList := make([]bgp.ParameterCapabilityInterface, 0)
	for _, c := range fsm.capMap[bgp.BGP_CAP_MULTIPROTOCOL] {
		if c.(*bgp.CapMultiProtocol).CapValue == rf {
			continue
		}
		newList = append(newList, c)
	}
	fsm.capMap[bgp.BGP_CAP_MULTIPROTOCOL] = newList
	return n
}

func (fsm *fsm) handlingError(m *bgp.BGPMessage, e error, useRevisedError bool) bgp.ErrorHandling {
	// ineffectual assignment to handling (ineffassign)
	var handling bgp.ErrorHandling
	if m.Header.Type == bgp.BGP_MSG_UPDATE && useRevisedError {
		factor := e.(*bgp.MessageError)
		handling = factor.ErrorHandling
		switch handling {
		case bgp.ERROR_HANDLING_ATTRIBUTE_DISCARD:
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
				"error": e,
			}).Warn("Some attributes were discarded")
			fsm.lock.RUnlock()
		case bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW:
			m.Body = bgp.TreatAsWithdraw(m.Body.(*bgp.BGPUpdate))
			fsm.lock.RLock()
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
				"error": e,
			}).Warn("the received Update message was treated as withdraw")
			fsm.lock.RUnlock()
		case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
			rf := extractRouteFamily(factor.ErrorAttribute)
			if rf == nil {
				fsm.lock.RLock()
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
				}).Warn("Error occurred during AFI/SAFI disabling")
				fsm.lock.RUnlock()
			} else {
				n := fsm.afiSafiDisable(*rf)
				fsm.lock.RLock()
				log.WithFields(log.Fields{
					"Topic": "Peer",
					"Key":   fsm.pConf.State.NeighborAddress,
					"State": fsm.state.String(),
					"error": e,
				}).Warnf("Capability %s was disabled", n)
				fsm.lock.RUnlock()
			}
		}
	} else {
		handling = bgp.ERROR_HANDLING_SESSION_RESET
	}
	return handling
}

func (fsm *fsm) recvMessageWithError() (*fsmMsg, error) {
	sendToStateReasonCh := func(typ fsmStateReasonType, notif *bgp.BGPMessage) {
		// probably doesn't happen but be cautious
		select {
		case fsm.stateReasonCh <- *newfsmStateReason(typ, notif, nil):
		default:
		}
	}

	headerBuf, err := readAll(fsm.conn, bgp.BGP_HEADER_LENGTH)
	if err != nil {
		sendToStateReasonCh(fsmReadFailed, nil)
		return nil, err
	}

	hd := &bgp.BGPHeader{}
	err = hd.DecodeFromBytes(headerBuf)
	if err != nil {
		fsm.bgpMessageStateUpdate(0, true)
		fsm.lock.RLock()
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   fsm.pConf.State.NeighborAddress,
			"State": fsm.state.String(),
			"error": err,
		}).Warn("Session will be reset due to malformed BGP Header")
		fmsg := &fsmMsg{
			fsm:     fsm,
			MsgType: fsmMsgBGPMessage,
			MsgSrc:  fsm.pConf.State.NeighborAddress,
			MsgData: err,
		}
		fsm.lock.RUnlock()
		return fmsg, err
	}

	bodyBuf, err := readAll(fsm.conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if err != nil {
		sendToStateReasonCh(fsmReadFailed, nil)
		return nil, err
	}

	now := time.Now()
	handling := bgp.ERROR_HANDLING_NONE

	fsm.lock.RLock()
	useRevisedError := fsm.pConf.ErrorHandling.Config.TreatAsWithdraw
	options := fsm.marshallingOptions
	fsm.lock.RUnlock()

	m, err := bgp.ParseBGPBody(hd, bodyBuf, options)
	if err != nil {
		handling = fsm.handlingError(m, err, useRevisedError)
		fsm.bgpMessageStateUpdate(0, true)
	} else {
		fsm.bgpMessageStateUpdate(m.Header.Type, true)
		err = bgp.ValidateBGPMessage(m)
	}
	fsm.lock.RLock()
	fmsg := &fsmMsg{
		fsm:       fsm,
		MsgType:   fsmMsgBGPMessage,
		MsgSrc:    fsm.pConf.State.NeighborAddress,
		timestamp: now,
	}
	fsm.lock.RUnlock()

	switch handling {
	case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
		fmsg.MsgData = m
		return fmsg, nil
	case bgp.ERROR_HANDLING_SESSION_RESET:
		fsm.lock.RLock()
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   fsm.pConf.State.NeighborAddress,
			"State": fsm.state.String(),
			"error": err,
		}).Warn("Session will be reset due to malformed BGP message")
		fsm.lock.RUnlock()
		fmsg.MsgData = err
		return fmsg, err
	default:
		fmsg.MsgData = m

		fsm.lock.RLock()
		establishedState := fsm.state == bgp.BGP_FSM_ESTABLISHED
		fsm.lock.RUnlock()

		if establishedState {
			switch m.Header.Type {
			case bgp.BGP_MSG_ROUTE_REFRESH:
				fmsg.MsgType = fsmMsgRouteRefresh
			case bgp.BGP_MSG_UPDATE:
				// if the length of fsm.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				select {
				case fsm.holdTimerResetCh <- true:
				default:
				}
				body := m.Body.(*bgp.BGPUpdate)
				isEBGP := fsm.pConf.IsEBGPPeer(fsm.gConf)
				isConfed := fsm.pConf.IsConfederationMember(fsm.gConf)

				fmsg.payload = make([]byte, len(headerBuf)+len(bodyBuf))
				copy(fmsg.payload, headerBuf)
				copy(fmsg.payload[len(headerBuf):], bodyBuf)

				fsm.lock.RLock()
				rfMap := fsm.rfMap
				fsm.lock.RUnlock()
				ok, err := bgp.ValidateUpdateMsg(body, rfMap, isEBGP, isConfed)
				if !ok {
					handling = fsm.handlingError(m, err, useRevisedError)
				}
				if handling == bgp.ERROR_HANDLING_SESSION_RESET {
					fsm.lock.RLock()
					log.WithFields(log.Fields{
						"Topic": "Peer",
						"Key":   fsm.pConf.State.NeighborAddress,
						"State": fsm.state.String(),
						"error": err,
					}).Warn("Session will be reset due to malformed BGP update message")
					fsm.lock.RUnlock()
					fmsg.MsgData = err
					return fmsg, err
				}

				if routes := len(body.WithdrawnRoutes); routes > 0 {
					fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
					fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
				} else if attr := getPathAttrFromBGPUpdate(body, bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI); attr != nil {
					mpUnreach := attr.(*bgp.PathAttributeMpUnreachNLRI)
					if routes = len(mpUnreach.Value); routes > 0 {
						fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
						fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
					}
				}

				table.UpdatePathAttrs4ByteAs(body)
				if err = table.UpdatePathAggregator4ByteAs(body); err != nil {
					fmsg.MsgData = err
					return fmsg, err
				}

				fsm.lock.RLock()
				peerInfo := fsm.peerInfo
				fsm.lock.RUnlock()
				fmsg.PathList = table.ProcessMessage(m, peerInfo, fmsg.timestamp)
				fallthrough
			case bgp.BGP_MSG_KEEPALIVE:
				// if the length of fsm.holdTimerResetCh
				// isn't zero, the timer will be reset
				// soon anyway.
				select {
				case fsm.holdTimerResetCh <- true:
				default:
				}
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					return nil, nil
				}
			case bgp.BGP_MSG_NOTIFICATION:
				body := m.Body.(*bgp.BGPNotification)
				if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
					communication, rest := decodeAdministrativeCommunication(body.Data)
					fsm.lock.RLock()
					log.WithFields(log.Fields{
						"Topic":               "Peer",
						"Key":                 fsm.pConf.State.NeighborAddress,
						"Code":                body.ErrorCode,
						"Subcode":             body.ErrorSubcode,
						"Communicated-Reason": communication,
						"Data":                rest,
					}).Warn("received notification")
					fsm.lock.RUnlock()
				} else {
					fsm.lock.RLock()
					log.WithFields(log.Fields{
						"Topic":   "Peer",
						"Key":     fsm.pConf.State.NeighborAddress,
						"Code":    body.ErrorCode,
						"Subcode": body.ErrorSubcode,
						"Data":    body.Data,
					}).Warn("received notification")
					fsm.lock.RUnlock()
				}

				fsm.lock.RLock()
				s := fsm.pConf.GracefulRestart.State
				hardReset := s.Enabled && s.NotificationEnabled && body.ErrorCode == bgp.BGP_ERROR_CEASE && body.ErrorSubcode == bgp.BGP_ERROR_SUB_HARD_RESET
				fsm.lock.RUnlock()
				if hardReset {
					sendToStateReasonCh(fsmHardReset, m)
				} else {
					sendToStateReasonCh(fsmNotificationRecv, m)
				}
				return nil, nil
			}
		}
	}
	return fmsg, nil
}

func (fsm *fsm) recvMessage(ctx context.Context, wg *sync.WaitGroup) error {
	defer func() {
		fsm.msgCh.Close()
		wg.Done()
	}()
	fmsg, _ := fsm.recvMessageWithError()
	if fmsg != nil {
		fsm.msgCh.In() <- fmsg
	}
	return nil
}

func (fsm *fsm) changeadminState(s adminState) error {
	fsm.lock.Lock()
	defer fsm.lock.Unlock()

	if fsm.adminState != s {
		log.WithFields(log.Fields{
			"Topic":      "Peer",
			"Key":        fsm.pConf.State.NeighborAddress,
			"State":      fsm.state.String(),
			"adminState": s.String(),
		}).Debug("admin state changed")

		fsm.adminState = s
		fsm.pConf.State.AdminDown = !fsm.pConf.State.AdminDown

		switch s {
		case adminStateUp:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
			}).Info("Administrative start")
		case adminStateDown:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
			}).Info("Administrative shutdown")
		case adminStatePfxCt:
			log.WithFields(log.Fields{
				"Topic": "Peer",
				"Key":   fsm.pConf.State.NeighborAddress,
				"State": fsm.state.String(),
			}).Info("Administrative shutdown(Prefix limit reached)")
		}

	} else {
		log.WithFields(log.Fields{
			"Topic": "Peer",
			"Key":   fsm.pConf.State.NeighborAddress,
			"State": fsm.state.String(),
		}).Warn("cannot change to the same state")

		return fmt.Errorf("cannot change to the same state")
	}
	return nil
}
