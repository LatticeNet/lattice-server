package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/LatticeNet/lattice-sdk/model"
)

// Which plugin records read the fleet (design 28).
//
// A committed vpn-core write advances the generation (share_fleet_changes.go)
// and used to expire every cached plugin share body, because core could not
// tell which records read vpn-core. A subscription plugin that declares
// depends_on on its subscription service now names them: every record whose
// transitive sources include the fleet (a fleet record, a collection with a
// fleet member, a provider record that pulls one in, a file built from one).
//
// On each advance core asks every such plugin once, off the write path, and
// then expires only the bodies of shares whose record the answer names. A
// share whose record it does not name keeps its body, and its source is
// carried to the new generation so the change does not make it due either.
// When the plugin does not declare the method, or the call fails, times out
// or answers malformed, every share of the plugin is expired as before:
// unknown is treated as dependent, never as independent.
//
// Request {} ; reply {"records":[{"id":"<subscription id>","revision":"..."}],"version":"..."}.
// revision and version are the plugin's own and optional; core reads ids.

const (
	fleetDependsMethod  = "depends_on"
	fleetDependsTimeout = 10 * time.Second
	// maxFleetDependsRecords bounds one answer, and maxFleetDependsIDBytes
	// one record id in it.
	maxFleetDependsRecords = 1 << 16
	maxFleetDependsIDBytes = 256
)

// fleetDependsState holds what the dependency answers need.
type fleetDependsState struct {
	// call asks a plugin's depends_on. Nil calls the plugin's declared
	// method; tests set it, and a set call counts as declared by every
	// plugin.
	call func(ctx context.Context, pluginID string) ([]byte, error)
	// wg counts answers still being resolved, so tests can wait for them.
	wg sync.WaitGroup
}

type fleetDependsReply struct {
	Records []fleetDependsRecord `json:"records"`
	Version string               `json:"version,omitempty"`
}

type fleetDependsRecord struct {
	ID       string `json:"id"`
	Revision string `json:"revision,omitempty"`
}

// decodeFleetDependsReply reads a depends_on answer into the set of record
// ids that read the fleet. A missing records list, an id that is empty, too
// long or holds a control character, or an answer over the bound is refused.
func decodeFleetDependsReply(raw []byte) (map[string]bool, error) {
	var reply struct {
		Records *[]fleetDependsRecord `json:"records"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		return nil, fmt.Errorf("depends_on reply: %w", err)
	}
	if reply.Records == nil {
		return nil, errors.New("depends_on reply has no records list")
	}
	if len(*reply.Records) > maxFleetDependsRecords {
		return nil, fmt.Errorf("depends_on reply names more than %d records", maxFleetDependsRecords)
	}
	out := make(map[string]bool, len(*reply.Records))
	for _, record := range *reply.Records {
		if record.ID == "" || len(record.ID) > maxFleetDependsIDBytes || strings.ContainsFunc(record.ID, unicode.IsControl) {
			return nil, errors.New("depends_on reply names an invalid record id")
		}
		out[record.ID] = true
	}
	return out, nil
}

// fleetDependsDeclared reports whether a plugin answers depends_on: it is
// active and its manifest declares the method on its subscription service.
func (s *Server) fleetDependsDeclared(pluginID string) bool {
	if s.substoreCatalogue.deps.call != nil {
		return true
	}
	if !s.pluginIsActive(pluginID) {
		return false
	}
	loaded, ok := s.loadedPlugin(pluginID)
	if !ok {
		return false
	}
	contract, ok := loaded.Manifest.InterfaceFor(pluginID + "/subscription")
	if !ok {
		return false
	}
	_, ok = contract.MethodContract(fleetDependsMethod)
	return ok
}

func (s *Server) callFleetDepends(ctx context.Context, pluginID string) ([]byte, error) {
	if call := s.substoreCatalogue.deps.call; call != nil {
		return call(ctx, pluginID)
	}
	return s.callRuntimePluginService(ctx, pluginID, pluginID+"/subscription", fleetDependsMethod, json.RawMessage("{}"), nil, nil)
}

// expirePluginSharesForFleetChange is what a generation advance does to the
// plugin share bodies: for a plugin that answers depends_on, ask it off the
// caller's path and expire only the dependent shares; for any other plugin,
// expire every share now.
func (s *Server) expirePluginSharesForFleetChange(generation uint64, now time.Time) {
	byPlugin := map[string][]model.SubscriptionShare{}
	for _, share := range s.store.SubscriptionSharesUnordered() {
		if share.Source.Kind == model.ShareSourcePlugin {
			byPlugin[share.Source.PluginID] = append(byPlugin[share.Source.PluginID], share)
		}
	}
	for pluginID, shares := range byPlugin {
		if s.fleetDependsDeclared(pluginID) {
			s.substoreCatalogue.deps.wg.Add(1)
			go func() {
				defer s.substoreCatalogue.deps.wg.Done()
				s.expireFleetDependentShares(pluginID, shares, generation)
			}()
			continue
		}
		for _, share := range shares {
			s.subscriptionCache.ExpireShare(share.ID, now)
		}
	}
}

// expireFleetDependentShares asks one plugin which records read the fleet
// and expires the bodies of those records' shares. Every other share's
// source that was current before this generation is carried to it, so the
// fleet change does not make it due.
func (s *Server) expireFleetDependentShares(pluginID string, shares []model.SubscriptionShare, generation uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), fleetDependsTimeout)
	defer cancel()
	raw, err := s.callFleetDepends(ctx, pluginID)
	var dependent map[string]bool
	if err == nil {
		dependent, err = decodeFleetDependsReply(raw)
	}
	now := s.now()
	if err != nil {
		s.logger.Printf("sub-store %s %s: %v; expiring every share of the plugin", pluginID, fleetDependsMethod, err)
		for _, share := range shares {
			s.subscriptionCache.ExpireShare(share.ID, now)
		}
		return
	}
	carried := map[string]bool{}
	for _, share := range shares {
		record := share.Source.SubscriptionID
		if record == "" || dependent[record] {
			s.subscriptionCache.ExpireShare(share.ID, now)
			continue
		}
		if carried[record] {
			continue
		}
		carried[record] = true
		publication := s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: pluginID, subscriptionID: record})
		publication.mu.Lock()
		if publication.vpnGen == generation-1 {
			publication.vpnGen = generation
		}
		publication.mu.Unlock()
	}
}
