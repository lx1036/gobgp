package server

import (
	"fmt"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/pkg/packet/bgp"
	log "github.com/sirupsen/logrus"
	"net"
	"time"
)

type watchEventType string

const (
	watchEventTypeBestPath   watchEventType = "bestpath"
	watchEventTypePreUpdate  watchEventType = "preupdate"
	watchEventTypePostUpdate watchEventType = "postupdate"
	watchEventTypePeerState  watchEventType = "peerstate"
	watchEventTypeTable      watchEventType = "table"
	watchEventTypeRecvMsg    watchEventType = "receivedmessage"
)

type watchEvent interface {
}

type watchEventUpdate struct {
	Message      *bgp.BGPMessage
	PeerAS       uint32
	LocalAS      uint32
	PeerAddress  net.IP
	LocalAddress net.IP
	PeerID       net.IP
	FourBytesAs  bool
	Timestamp    time.Time
	Payload      []byte
	PostPolicy   bool
	Init         bool
	PathList     []*table.Path
	Neighbor     *config.Neighbor
}

type watchEventPeerState struct {
	PeerAS        uint32
	LocalAS       uint32
	PeerAddress   net.IP
	LocalAddress  net.IP
	PeerPort      uint16
	LocalPort     uint16
	PeerID        net.IP
	SentOpen      *bgp.BGPMessage
	RecvOpen      *bgp.BGPMessage
	State         bgp.FSMState
	StateReason   *fsmStateReason
	AdminState    adminState
	Timestamp     time.Time
	PeerInterface string
}

type watchEventAdjIn struct {
	PathList []*table.Path
}

type watchEventTable struct {
	RouterID string
	PathList map[string][]*table.Path
	Neighbor []*config.Neighbor
}

type watchEventBestPath struct {
	PathList      []*table.Path
	MultiPathList [][]*table.Path
	Vrf           map[uint32]bool
}

type watchEventMessage struct {
	Message      *bgp.BGPMessage
	PeerAS       uint32
	LocalAS      uint32
	PeerAddress  net.IP
	LocalAddress net.IP
	PeerID       net.IP
	FourBytesAs  bool
	Timestamp    time.Time
	IsSent       bool
}

type watchOptions struct {
	bestpath       bool
	preUpdate      bool
	postUpdate     bool
	peerState      bool
	initBest       bool
	initUpdate     bool
	initPostUpdate bool
	initPeerState  bool
	nonEstablished bool
	tableName      string
	recvMessage    bool
	peerAddress    string
}

type watchOption func(*watchOptions)

func watchBestPath(current bool) watchOption {
	return func(o *watchOptions) {
		o.bestpath = true
		if current {
			o.initBest = true
		}
	}
}

func watchUpdate(current bool, peerAddress string) watchOption {
	return func(o *watchOptions) {
		o.preUpdate = true
		if current {
			o.initUpdate = true
		}
		o.peerAddress = peerAddress
	}
}

func watchPostUpdate(current bool, peerAddress string) watchOption {
	return func(o *watchOptions) {
		o.postUpdate = true
		if current {
			o.initPostUpdate = true
		}
		o.peerAddress = peerAddress
	}
}

func watchPeerState(current, includeNonEstablished bool) watchOption {
	return func(o *watchOptions) {
		o.peerState = true
		if current {
			o.initPeerState = true
			if includeNonEstablished {
				o.nonEstablished = true
			}
		}
	}
}

func watchTableName(name string) watchOption {
	return func(o *watchOptions) {
		o.tableName = name
	}
}

func watchMessage(isSent bool) watchOption {
	return func(o *watchOptions) {
		if isSent {
			log.WithFields(log.Fields{
				"Topic": "Server",
			}).Warn("watch event for sent messages is not implemented yet")
			// o.sentMessage = true
		} else {
			o.recvMessage = true
		}
	}
}

type watcher struct {
	opts   watchOptions
	realCh chan watchEvent
	ch     chan watchEvent
	s      *BgpServer
}

func (w *watcher) Event() <-chan watchEvent {
	return w.realCh
}

func (w *watcher) Generate(t watchEventType) error {
	return w.s.mgmtOperation(func() error {
		switch t {
		case watchEventTypePreUpdate:
			pathList := make([]*table.Path, 0)
			for _, peer := range w.s.neighborMap {
				pathList = append(pathList, peer.adjRibIn.PathList(peer.configuredRFlist(), false)...)
			}
			w.notify(&watchEventAdjIn{PathList: clonePathList(pathList)})
		case watchEventTypeTable:
			rib := w.s.globalRib
			as := uint32(0)
			id := table.GLOBAL_RIB_NAME
			if len(w.opts.tableName) > 0 {
				peer, ok := w.s.neighborMap[w.opts.tableName]
				if !ok {
					return fmt.Errorf("neighbor that has %v doesn't exist", w.opts.tableName)
				}
				if !peer.isRouteServerClient() {
					return fmt.Errorf("neighbor %v doesn't have local rib", w.opts.tableName)
				}
				id = peer.ID()
				as = peer.AS()
				rib = w.s.rsRib
			}

			pathList := func() map[string][]*table.Path {
				pathList := make(map[string][]*table.Path)
				for _, t := range rib.Tables {
					for _, dst := range t.GetDestinations() {
						if paths := dst.GetKnownPathList(id, as); len(paths) > 0 {
							pathList[dst.GetNlri().String()] = clonePathList(paths)
						}
					}
				}
				return pathList
			}()
			l := make([]*config.Neighbor, 0, len(w.s.neighborMap))
			for _, peer := range w.s.neighborMap {
				l = append(l, w.s.toConfig(peer, false))
			}
			w.notify(&watchEventTable{PathList: pathList, Neighbor: l})
		default:
			return fmt.Errorf("unsupported type %v", t)
		}
		return nil
	}, false)
}

func (w *watcher) notify(v watchEvent) {
	w.realCh <- v
}

func (w *watcher) Stop() {
	w.s.mgmtOperation(func() error {
		for k, l := range w.s.watcherMap {
			for i, v := range l {
				if w == v {
					w.s.watcherMap[k] = append(l[:i], l[i+1:]...)
					break
				}
			}
		}

		// the loop function goroutine might be blocked for
		// writing to realCh. make sure it finishes.
		for range w.realCh {
		}
		return nil
	}, false)
}

func (s *BgpServer) isWatched(typ watchEventType) bool {
	return len(s.watcherMap[typ]) != 0
}

func (s *BgpServer) notifyWatcher(typ watchEventType, ev watchEvent) {
	for _, w := range s.watcherMap[typ] {
		w.notify(ev)
	}
}

func (s *BgpServer) watch(opts ...watchOption) (w *watcher) {
	s.mgmtOperation(func() error {
		w = &watcher{
			s:      s,
			realCh: make(chan watchEvent, 8),
			ch:     make(chan watchEvent, 8),
		}

		for _, opt := range opts {
			opt(&w.opts)
		}

		register := func(t watchEventType, w *watcher) {
			s.watcherMap[t] = append(s.watcherMap[t], w)
		}

		if w.opts.bestpath {
			register(watchEventTypeBestPath, w)
		}
		if w.opts.preUpdate {
			register(watchEventTypePreUpdate, w)
		}
		if w.opts.postUpdate {
			register(watchEventTypePostUpdate, w)
		}
		if w.opts.peerState {
			register(watchEventTypePeerState, w)
		}
		if w.opts.initPeerState {
			for _, peer := range s.neighborMap {
				if !w.opts.nonEstablished {
					peer.fsm.lock.RLock()
					notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
					peer.fsm.lock.RUnlock()
					if notEstablished {
						continue
					}
				}
				w.notify(newWatchEventPeerState(peer, nil))
			}
		}
		if w.opts.initBest && s.active() == nil {
			w.notify(&watchEventBestPath{
				PathList:      s.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, 0, nil),
				MultiPathList: s.globalRib.GetBestMultiPathList(table.GLOBAL_RIB_NAME, nil),
			})
		}
		if w.opts.initUpdate {
			for _, peer := range s.neighborMap {
				peer.fsm.lock.RLock()
				notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
				peerAddress := peer.fsm.peerInfo.Address.String()
				peer.fsm.lock.RUnlock()
				if notEstablished {
					continue
				}
				if len(w.opts.peerAddress) > 0 && w.opts.peerAddress != peerAddress {
					continue
				}
				configNeighbor := w.s.toConfig(peer, false)
				for _, rf := range peer.configuredRFlist() {
					peer.fsm.lock.RLock()
					_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
					l, _ := peer.fsm.LocalHostPort()
					update := &watchEventUpdate{
						PeerAS:       peer.fsm.peerInfo.AS,
						LocalAS:      peer.fsm.peerInfo.LocalAS,
						PeerAddress:  peer.fsm.peerInfo.Address,
						LocalAddress: net.ParseIP(l),
						PeerID:       peer.fsm.peerInfo.ID,
						FourBytesAs:  y,
						Init:         true,
						PostPolicy:   false,
						Neighbor:     configNeighbor,
						PathList:     peer.adjRibIn.PathList([]bgp.RouteFamily{rf}, false),
					}
					peer.fsm.lock.RUnlock()
					w.notify(update)

					eor := bgp.NewEndOfRib(rf)
					eorBuf, _ := eor.Serialize()
					peer.fsm.lock.RLock()
					update = &watchEventUpdate{
						Message:      eor,
						PeerAS:       peer.fsm.peerInfo.AS,
						LocalAS:      peer.fsm.peerInfo.LocalAS,
						PeerAddress:  peer.fsm.peerInfo.Address,
						LocalAddress: net.ParseIP(l),
						PeerID:       peer.fsm.peerInfo.ID,
						FourBytesAs:  y,
						Timestamp:    time.Now(),
						Init:         true,
						Payload:      eorBuf,
						PostPolicy:   false,
						Neighbor:     configNeighbor,
					}
					peer.fsm.lock.RUnlock()
					w.notify(update)
				}
			}
		}
		if w.opts.initPostUpdate && s.active() == nil {
			for _, rf := range s.globalRib.GetRFlist() {
				if len(s.globalRib.Tables[rf].GetDestinations()) == 0 {
					continue
				}
				pathsByPeer := make(map[*table.PeerInfo][]*table.Path)
				for _, path := range s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.RouteFamily{rf}) {
					pathsByPeer[path.GetSource()] = append(pathsByPeer[path.GetSource()], path)
				}
				for peerInfo, paths := range pathsByPeer {
					// create copy which can be access to without mutex
					var configNeighbor *config.Neighbor
					peerAddress := peerInfo.Address.String()
					if peer, ok := s.neighborMap[peerAddress]; ok {
						configNeighbor = w.s.toConfig(peer, false)
					}
					if w.opts.peerAddress != "" && w.opts.peerAddress != peerAddress {
						continue
					}

					w.notify(&watchEventUpdate{
						PeerAS:      peerInfo.AS,
						PeerAddress: peerInfo.Address,
						PeerID:      peerInfo.ID,
						PostPolicy:  true,
						Neighbor:    configNeighbor,
						PathList:    paths,
						Init:        true,
					})

					eor := bgp.NewEndOfRib(rf)
					eorBuf, _ := eor.Serialize()
					w.notify(&watchEventUpdate{
						Message:     eor,
						PeerAS:      peerInfo.AS,
						PeerAddress: peerInfo.Address,
						PeerID:      peerInfo.ID,
						Timestamp:   time.Now(),
						Payload:     eorBuf,
						PostPolicy:  true,
						Neighbor:    configNeighbor,
						Init:        true,
					})
				}
			}
		}
		if w.opts.recvMessage {
			register(watchEventTypeRecvMsg, w)
		}

		return nil
	}, false)
	return w
}
