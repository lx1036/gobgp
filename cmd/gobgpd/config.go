package main

import (
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"

	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/internal/pkg/config"
	"github.com/osrg/gobgp/internal/pkg/table"
	"github.com/osrg/gobgp/pkg/server"
)

// ReadConfigFile parses a config file into a BgpConfigSet which can be applied
// using InitialConfig and UpdateConfig.
func ReadConfigFile(configFile, configType string) (*config.BgpConfigSet, error) {
	return config.ReadConfigfile(configFile, configType)
}

func assignGlobalpolicy(ctx context.Context, bgpServer *server.BgpServer, a *config.ApplyPolicyConfig) {
	toDefaultTable := func(r config.DefaultPolicyType) table.RouteType {
		var def table.RouteType
		switch r {
		case config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE:
			def = table.ROUTE_TYPE_ACCEPT
		case config.DEFAULT_POLICY_TYPE_REJECT_ROUTE:
			def = table.ROUTE_TYPE_REJECT
		}
		return def
	}
	toPolicies := func(r []string) []*table.Policy {
		p := make([]*table.Policy, 0, len(r))
		for _, n := range r {
			p = append(p, &table.Policy{
				Name: n,
			})
		}
		return p
	}

	def := toDefaultTable(a.DefaultImportPolicy)
	ps := toPolicies(a.ImportPolicyList)
	bgpServer.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: table.NewAPIPolicyAssignmentFromTableStruct(&table.PolicyAssignment{
			Name:     table.GLOBAL_RIB_NAME,
			Type:     table.POLICY_DIRECTION_IMPORT,
			Policies: ps,
			Default:  def,
		}),
	})

	def = toDefaultTable(a.DefaultExportPolicy)
	ps = toPolicies(a.ExportPolicyList)
	bgpServer.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: table.NewAPIPolicyAssignmentFromTableStruct(&table.PolicyAssignment{
			Name:     table.GLOBAL_RIB_NAME,
			Type:     table.POLICY_DIRECTION_EXPORT,
			Policies: ps,
			Default:  def,
		}),
	})

}

func addPeerGroups(ctx context.Context, bgpServer *server.BgpServer, addedPg []config.PeerGroup) {
	for _, pg := range addedPg {
		log.Infof("PeerGroup %s is added", pg.Config.PeerGroupName)
		if err := bgpServer.AddPeerGroup(ctx, &api.AddPeerGroupRequest{
			PeerGroup: config.NewPeerGroupFromConfigStruct(&pg),
		}); err != nil {
			log.Warn(err)
		}
	}
}

func deletePeerGroups(ctx context.Context, bgpServer *server.BgpServer, deletedPg []config.PeerGroup) {
	for _, pg := range deletedPg {
		log.Infof("PeerGroup %s is deleted", pg.Config.PeerGroupName)
		if err := bgpServer.DeletePeerGroup(ctx, &api.DeletePeerGroupRequest{
			Name: pg.Config.PeerGroupName,
		}); err != nil {
			log.Warn(err)
		}
	}
}

func updatePeerGroups(ctx context.Context, bgpServer *server.BgpServer, updatedPg []config.PeerGroup) bool {
	for _, pg := range updatedPg {
		log.Infof("PeerGroup %s is updated", pg.Config.PeerGroupName)
		if u, err := bgpServer.UpdatePeerGroup(ctx, &api.UpdatePeerGroupRequest{
			PeerGroup: config.NewPeerGroupFromConfigStruct(&pg),
		}); err != nil {
			log.Warn(err)
		} else {
			return u.NeedsSoftResetIn
		}
	}
	return false
}

func addDynamicNeighbors(ctx context.Context, bgpServer *server.BgpServer, dynamicNeighbors []config.DynamicNeighbor) {
	for _, dn := range dynamicNeighbors {
		log.Infof("Dynamic Neighbor %s is added to PeerGroup %s", dn.Config.Prefix, dn.Config.PeerGroup)
		if err := bgpServer.AddDynamicNeighbor(ctx, &api.AddDynamicNeighborRequest{
			DynamicNeighbor: &api.DynamicNeighbor{
				Prefix:    dn.Config.Prefix,
				PeerGroup: dn.Config.PeerGroup,
			},
		}); err != nil {
			log.Warn(err)
		}
	}
}

func addNeighbors(ctx context.Context, bgpServer *server.BgpServer, added []config.Neighbor) {
	for _, p := range added {
		log.Infof("Peer %v is added", p.State.NeighborAddress)
		if err := bgpServer.AddPeer(ctx, &api.AddPeerRequest{
			Peer: config.NewPeerFromConfigStruct(&p),
		}); err != nil {
			log.Warn(err)
		}
	}
}

func deleteNeighbors(ctx context.Context, bgpServer *server.BgpServer, deleted []config.Neighbor) {
	for _, p := range deleted {
		log.Infof("Peer %v is deleted", p.State.NeighborAddress)
		if err := bgpServer.DeletePeer(ctx, &api.DeletePeerRequest{
			Address: p.State.NeighborAddress,
		}); err != nil {
			log.Warn(err)
		}
	}
}

func updateNeighbors(ctx context.Context, bgpServer *server.BgpServer, updated []config.Neighbor) bool {
	for _, p := range updated {
		log.Infof("Peer %v is updated", p.State.NeighborAddress)
		if u, err := bgpServer.UpdatePeer(ctx, &api.UpdatePeerRequest{
			Peer: config.NewPeerFromConfigStruct(&p),
		}); err != nil {
			log.Warn(err)
		} else {
			return u.NeedsSoftResetIn
		}
	}
	return false
}

// InitialConfig applies initial configuration to a pristine gobgp instance. It
// can only be called once for an instance. Subsequent changes to the
// configuration can be applied using UpdateConfig. The BgpConfigSet can be
// obtained by calling ReadConfigFile. If graceful restart behavior is desired,
// pass true for isGracefulRestart. Otherwise, pass false.
func InitialConfig(ctx context.Context, bgpServer *server.BgpServer, newConfig *config.BgpConfigSet, isGracefulRestart bool) (*config.BgpConfigSet, error) {
	if err := bgpServer.StartBgp(ctx, &api.StartBgpRequest{
		Global: config.NewGlobalFromConfigStruct(&newConfig.Global),
	}); err != nil {
		log.Fatalf("failed to set global config: %s", err)
	}

	p := config.ConfigSetToRoutingPolicy(newConfig)
	rp, err := table.NewAPIRoutingPolicyFromConfigStruct(p)
	if err != nil {
		log.Warn(err)
	} else {
		bgpServer.SetPolicies(ctx, &api.SetPoliciesRequest{
			DefinedSets: rp.DefinedSets,
			Policies:    rp.Policies,
		})
	}

	assignGlobalpolicy(ctx, bgpServer, &newConfig.Global.ApplyPolicy.Config)

	added := newConfig.Neighbors
	addedPg := newConfig.PeerGroups
	if isGracefulRestart {
		for i, n := range added {
			if n.GracefulRestart.Config.Enabled {
				added[i].GracefulRestart.State.LocalRestarting = true
			}
		}
	}

	addPeerGroups(ctx, bgpServer, addedPg)
	addDynamicNeighbors(ctx, bgpServer, newConfig.DynamicNeighbors)
	addNeighbors(ctx, bgpServer, added)
	return newConfig, nil
}

// UpdateConfig updates the configuration of a running gobgp instance.
// InitialConfig must have been called once before this can be called for
// subsequent changes to config. The differences are that this call 1) does not
// hangle graceful restart and 2) requires a BgpConfigSet for the previous
// configuration so that it can compute the delta between it and the new
// config. The new BgpConfigSet can be obtained using ReadConfigFile.
func UpdateConfig(ctx context.Context, bgpServer *server.BgpServer, c, newConfig *config.BgpConfigSet) (*config.BgpConfigSet, error) {
	addedPg, deletedPg, updatedPg := config.UpdatePeerGroupConfig(c, newConfig)
	added, deleted, updated := config.UpdateNeighborConfig(c, newConfig)
	updatePolicy := config.CheckPolicyDifference(config.ConfigSetToRoutingPolicy(c), config.ConfigSetToRoutingPolicy(newConfig))

	if updatePolicy {
		log.Info("Policy config is updated")
		p := config.ConfigSetToRoutingPolicy(newConfig)
		rp, err := table.NewAPIRoutingPolicyFromConfigStruct(p)
		if err != nil {
			log.Warn(err)
		} else {
			bgpServer.SetPolicies(ctx, &api.SetPoliciesRequest{
				DefinedSets: rp.DefinedSets,
				Policies:    rp.Policies,
			})
		}
	}
	// global policy update
	if !newConfig.Global.ApplyPolicy.Config.Equal(&c.Global.ApplyPolicy.Config) {
		assignGlobalpolicy(ctx, bgpServer, &newConfig.Global.ApplyPolicy.Config)
		updatePolicy = true
	}

	addPeerGroups(ctx, bgpServer, addedPg)
	deletePeerGroups(ctx, bgpServer, deletedPg)
	needsSoftResetIn := updatePeerGroups(ctx, bgpServer, updatedPg)
	updatePolicy = updatePolicy || needsSoftResetIn
	addDynamicNeighbors(ctx, bgpServer, newConfig.DynamicNeighbors)
	addNeighbors(ctx, bgpServer, added)
	deleteNeighbors(ctx, bgpServer, deleted)
	needsSoftResetIn = updateNeighbors(ctx, bgpServer, updated)
	updatePolicy = updatePolicy || needsSoftResetIn

	if updatePolicy {
		if err := bgpServer.ResetPeer(ctx, &api.ResetPeerRequest{
			Address:   "",
			Direction: api.ResetPeerRequest_IN,
			Soft:      true,
		}); err != nil {
			log.Warn(err)
		}
	}
	return newConfig, nil
}
