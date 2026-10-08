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
// A change that revokes access (an identity disabled, a credential removed)
// must reach the bodies that carry it at once, so the advance never waits for
// the plugin. It expires, on the write path, every share whose record the
// plugin's answers have not shown to be independent: a record any answer has
// named, a record no answer has judged yet, and a record whose content has
// moved since it was judged (it may have gained a fleet source). Only a
// record the last answer left out, whose content has not moved since, keeps
// its body for the moment. Core then asks the plugin, off the write path and
// bound to the server's lifetime, and refines: a kept record the fresh answer
// names is expired, and a kept record it leaves out has its source carried to
// the new generation, so the change does not make it due either. The first
// advance after a start therefore expires every share of the plugin, as
// before the method existed.
//
// A record an answer has named stays dependent while it has a share, even
// when a later answer leaves it out. An empty or truncated answer from a
// plugin bug would otherwise keep every fleet-bound body cached until its
// TTL; the cost of the rule is one provider fetch per advance for a record an
// operator really did detach from the fleet, until the server restarts.
//
// When the plugin does not declare the method, or the call fails, times out
// or answers malformed, every share of the plugin is expired and the
// independent judgments are dropped: unknown is treated as dependent, never
// as independent.
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

	mu sync.Mutex
	// plugins is what each plugin's answers established.
	plugins map[string]*fleetDependsAnswers
	// ctx lives as long as the server. Close cancels it, so an ask in flight
	// stops with the server, and marks the state closed, so none starts
	// after.
	ctx    context.Context
	cancel context.CancelFunc
	closed bool
	// wg counts asks in flight, so Close and tests can wait for them.
	wg sync.WaitGroup
}

// fleetDependsAnswers is what one plugin's answers established. Neither map
// is written after it is stored; an answer replaces the whole value.
type fleetDependsAnswers struct {
	// dependent is every record with a share that an answer has named.
	dependent map[string]bool
	// independent is every record with a share that the last answer left
	// out, with the record's publication epoch when it was asked.
	independent map[string]uint64
}

// begin registers an ask and returns the server-lifetime context it runs
// under; ok is false once Close has run.
func (d *fleetDependsState) begin() (context.Context, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, false
	}
	if d.ctx == nil {
		d.ctx, d.cancel = context.WithCancel(context.Background())
	}
	d.wg.Add(1)
	return d.ctx, true
}

// close cancels every ask in flight, refuses new ones, and waits for the
// asks to finish until ctx ends.
func (d *fleetDependsState) close(ctx context.Context) {
	d.mu.Lock()
	d.closed = true
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// independentOf returns the records the plugin's last answer left out, with
// the epoch each was judged at. It is empty when no answer stands.
func (d *fleetDependsState) independentOf(pluginID string) map[string]uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if answers := d.plugins[pluginID]; answers != nil {
		return answers.independent
	}
	return nil
}

// learn records a fresh answer: named, and every record an earlier answer
// named, is dependent; every other record in epochs is independent at its
// epoch. Records without a share (absent from epochs) are dropped. It
// returns the dependent set, which the caller may read but not write.
func (d *fleetDependsState) learn(pluginID string, named map[string]bool, epochs map[string]uint64) map[string]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.plugins == nil {
		d.plugins = map[string]*fleetDependsAnswers{}
	}
	previous := d.plugins[pluginID]
	next := &fleetDependsAnswers{dependent: map[string]bool{}, independent: map[string]uint64{}}
	for record, epoch := range epochs {
		if named[record] || (previous != nil && previous.dependent[record]) {
			next.dependent[record] = true
		} else {
			next.independent[record] = epoch
		}
	}
	d.plugins[pluginID] = next
	return next.dependent
}

// forget drops a plugin's independent judgments after an unusable answer,
// keeping the records its earlier answers named.
func (d *fleetDependsState) forget(pluginID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if previous := d.plugins[pluginID]; previous != nil {
		d.plugins[pluginID] = &fleetDependsAnswers{dependent: previous.dependent}
	}
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

// fleetDependsEpoch is a record's publication epoch, which moves whenever its
// content does.
func (s *Server) fleetDependsEpoch(pluginID, record string) uint64 {
	publication := s.subscriptionPublicationStateFor(subscriptionRefreshKey{pluginID: pluginID, subscriptionID: record})
	publication.mu.Lock()
	defer publication.mu.Unlock()
	return publication.epoch
}

// expirePluginSharesForFleetChange is what a generation advance does to the
// plugin share bodies. For a plugin that answers depends_on it expires now
// every share its answers have not shown to be independent, then asks the
// plugin off the caller's path and refines; for any other plugin it expires
// every share now.
func (s *Server) expirePluginSharesForFleetChange(generation uint64, now time.Time) {
	byPlugin := map[string][]model.SubscriptionShare{}
	for _, share := range s.store.SubscriptionSharesUnordered() {
		if share.Source.Kind == model.ShareSourcePlugin {
			byPlugin[share.Source.PluginID] = append(byPlugin[share.Source.PluginID], share)
		}
	}
	deps := &s.substoreCatalogue.deps
	for pluginID, shares := range byPlugin {
		if !s.fleetDependsDeclared(pluginID) {
			s.expireFleetShares(shares, now)
			continue
		}
		kept := s.keepFleetIndependentShares(pluginID, shares, now)
		ctx, ok := deps.begin()
		if !ok {
			s.expireFleetShares(kept, now)
			continue
		}
		go func() {
			defer deps.wg.Done()
			s.refineFleetDependentShares(ctx, pluginID, shares, kept, generation)
		}()
	}
}

func (s *Server) expireFleetShares(shares []model.SubscriptionShare, now time.Time) {
	for _, share := range shares {
		s.subscriptionCache.ExpireShare(share.ID, now)
	}
}

// keepFleetIndependentShares expires every share whose record the plugin's
// last answer did not leave out at the record's current epoch, and returns
// the shares it kept.
func (s *Server) keepFleetIndependentShares(pluginID string, shares []model.SubscriptionShare, now time.Time) []model.SubscriptionShare {
	independent := s.substoreCatalogue.deps.independentOf(pluginID)
	var kept []model.SubscriptionShare
	for _, share := range shares {
		record := share.Source.SubscriptionID
		if epoch, ok := independent[record]; ok && record != "" && s.fleetDependsEpoch(pluginID, record) == epoch {
			kept = append(kept, share)
			continue
		}
		s.subscriptionCache.ExpireShare(share.ID, now)
	}
	return kept
}

// refineFleetDependentShares asks one plugin which records read the fleet,
// records the answer for the next advance, expires the kept shares whose
// record is dependent, and carries every other kept share's source that was
// current before this generation to it, so the fleet change does not make it
// due.
func (s *Server) refineFleetDependentShares(ctx context.Context, pluginID string, shares, kept []model.SubscriptionShare, generation uint64) {
	// Epochs are read before the ask, so content that moves while the plugin
	// answers is judged again on the next advance.
	epochs := map[string]uint64{}
	for _, share := range shares {
		if record := share.Source.SubscriptionID; record != "" {
			if _, ok := epochs[record]; !ok {
				epochs[record] = s.fleetDependsEpoch(pluginID, record)
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, fleetDependsTimeout)
	defer cancel()
	raw, err := s.callFleetDepends(ctx, pluginID)
	var named map[string]bool
	if err == nil {
		named, err = decodeFleetDependsReply(raw)
	}
	now := s.now()
	if err != nil {
		s.logger.Printf("sub-store %s %s: %v; expiring every share of the plugin", pluginID, fleetDependsMethod, err)
		s.substoreCatalogue.deps.forget(pluginID)
		s.expireFleetShares(kept, now)
		return
	}
	dependent := s.substoreCatalogue.deps.learn(pluginID, named, epochs)
	carried := map[string]bool{}
	for _, share := range kept {
		record := share.Source.SubscriptionID
		if dependent[record] {
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
