package store

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"time"
)

// Incident records and maintenance windows (keepalive P3).
//
// An incident is one problem on one subject (a node, or a monitor on a node)
// from the moment its hold elapsed until it resolved, with what the operator
// did about it (acknowledge, snooze) and what the phone was told. The server
// decides the lifecycle (internal/server/incidents.go); this file only keeps
// the records.
//
// Both live on the record-level bolt path when the hot store is on and in
// memory when it is off, like the notification outbox, and never enter the
// JSON state. An incident is written when it opens, resolves, is acknowledged
// or snoozed, and when a notification about it goes out; never per probe or
// per beat. Pending incidents (the hold still running) are not records at
// all: the server keeps them in memory, since most of them end within the
// hold and a restart re-derives them from the emitters' own evidence.
//
// These are operational history, not the evidence record: acknowledging,
// snoozing and editing a maintenance window are audited by the server.
//
// yagni: the buckets are created on first write and are not part of
// boltStateBuckets, so a whole-state import (ImportState, the one-time
// subscription secret migration) neither resets nor carries them; open
// incidents start over after that migration. Joining the import is the
// upgrade if that ever matters.

const (
	IncidentStateOpen         = "open"
	IncidentStateAcknowledged = "acknowledged"
	IncidentStateResolved     = "resolved"

	// IncidentNotifiedOpen and IncidentNotifiedResolved say what the phone
	// was last told about an incident; empty means nothing was sent.
	IncidentNotifiedOpen     = "open"
	IncidentNotifiedResolved = "resolved"

	// MaxIncidents bounds the records kept. Eviction takes the oldest
	// resolved incident; an open one is never evicted.
	MaxIncidents = 2000
	// IncidentRetention is how long a resolved incident is kept.
	IncidentRetention = 30 * 24 * time.Hour

	// MaxMaintenanceWindows bounds stored windows; windows that ended more
	// than MaintenanceWindowRetention ago are pruned first.
	MaxMaintenanceWindows      = 500
	MaintenanceWindowRetention = 30 * 24 * time.Hour

	maxIncidentText = 2048
)

// Incident is one opened problem on one subject.
type Incident struct {
	ID string `json:"id"`
	// Key names the subject and kind; at most one unresolved incident per
	// key exists at a time.
	Key       string `json:"key"`
	Kind      string `json:"kind"`
	Severity  string `json:"severity"`
	NodeID    string `json:"node_id,omitempty"`
	MonitorID string `json:"monitor_id,omitempty"`
	// Subject is the display name at open (node name, or monitor on node).
	Subject string `json:"subject,omitempty"`
	State   string `json:"state"`
	// Title and Detail are the open message the incident produced, which
	// an escalation repeats; Line is its share of a digest when several
	// incidents of one kind go out together.
	Title  string `json:"title,omitempty"`
	Detail string `json:"detail,omitempty"`
	Line   string `json:"line,omitempty"`
	// RecoveryTitle, RecoveryDetail and RecoveryLine are the same for the
	// recovery message, set when the incident resolves.
	RecoveryTitle  string `json:"recovery_title,omitempty"`
	RecoveryDetail string `json:"recovery_detail,omitempty"`
	RecoveryLine   string `json:"recovery_line,omitempty"`
	// Since is when the condition began (a node's last heartbeat, a
	// problem's start), FirstOpenedAt when the incident first opened and
	// OpenedAt when it last opened (a flap reopens the same record).
	Since         time.Time `json:"since,omitzero"`
	FirstOpenedAt time.Time `json:"first_opened_at"`
	OpenedAt      time.Time `json:"opened_at"`
	ResolvedAt    time.Time `json:"resolved_at,omitzero"`
	UpdatedAt     time.Time `json:"updated_at"`

	AckedBy string    `json:"acked_by,omitempty"`
	AckedAt time.Time `json:"acked_at,omitzero"`
	// AckCancelledOpen records that the acknowledgement cancelled an open
	// message that was owed: one a window, a snooze or flap damping held,
	// or a snooze reminder that fell due while acknowledged. Undoing the
	// acknowledgement owes it again.
	AckCancelledOpen bool      `json:"ack_cancelled_open,omitempty"`
	SnoozedBy        string    `json:"snoozed_by,omitempty"`
	SnoozedUntil     time.Time `json:"snoozed_until,omitzero"`

	// Notified is what the phone was last told (IncidentNotified*), and
	// NotifiedAt when. OpenNotifiedAt is when it was last told "open", which
	// starts the escalation clock. A recovery is owed only while Notified is
	// open.
	Notified       string    `json:"notified,omitempty"`
	NotifiedAt     time.Time `json:"notified_at,omitzero"`
	OpenNotifiedAt time.Time `json:"open_notified_at,omitzero"`
	// OwedOpen is set while an open message is owed and not yet sent: from
	// the moment the incident opens until the next evaluation sends it, or
	// for as long as a maintenance window, a snooze or flap damping holds
	// it. OwedRecovery is the same for the recovery, owed only when the
	// phone was told "open". Both survive a restart, so a decision taken
	// just before a crash is still sent after it.
	OwedOpen     bool `json:"owed_open,omitempty"`
	OwedRecovery bool `json:"owed_recovery,omitempty"`
	// OwedOpenRules names the rules still owed the open message when only
	// some are: the rules whose quiet-hours copy was withdrawn (because of
	// an acknowledgement since undone, or a snooze since ended early) while
	// the other rules had delivered theirs. The sweep sends it through these
	// rules alone once nothing holds the incident; OwedOpen, when set, owes
	// it through every rule and covers them. A later acknowledgement keeps
	// them for its own undo. Resolving keeps them until the recovery goes
	// out, which leaves them out since they never heard "down"; reopening
	// before then owes them the new open.
	OwedOpenRules []string `json:"owed_open_rules,omitempty"`
	// Suppressed is the last reason a message about this incident was held,
	// and SuppressedAt when.
	Suppressed   string    `json:"suppressed,omitempty"`
	SuppressedAt time.Time `json:"suppressed_at,omitzero"`

	// Flaps counts reopenings within the flap window; Flapping is set from
	// the third, and damps messages to one an hour until the incident stays
	// resolved for an hour.
	Flaps    int  `json:"flaps,omitempty"`
	Flapping bool `json:"flapping,omitempty"`

	// Escalated maps a rule id ("" for the no-rules broadcast) to when this
	// incident was escalated through it. Each rule escalates once.
	Escalated map[string]time.Time `json:"escalated,omitempty"`
	// NoEscalate marks an incident carried over from a page sent before
	// incident records existed; it is never escalated.
	NoEscalate bool `json:"no_escalate,omitempty"`
}

// Active reports whether the incident is still open (acknowledged or not).
func (i Incident) Active() bool {
	return i.State == IncidentStateOpen || i.State == IncidentStateAcknowledged
}

// MaintenanceWindow holds notifications for the nodes it covers between
// StartsAt and EndsAt. Incidents still open and close as usual.
type MaintenanceWindow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Reason    string    `json:"reason,omitempty"`
	NodeIDs   []string  `json:"node_ids,omitempty"`
	GroupIDs  []string  `json:"group_ids,omitempty"`
	StartsAt  time.Time `json:"starts_at"`
	EndsAt    time.Time `json:"ends_at"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ActiveAt reports whether the window holds notifications at t.
func (w MaintenanceWindow) ActiveAt(t time.Time) bool {
	return !t.Before(w.StartsAt) && t.Before(w.EndsAt)
}

// incidentBook is the in-memory copy. With the hot store on it mirrors bolt
// and is loaded from it on first use; without it, it is the only copy.
type incidentBook struct {
	loaded     bool
	loadedFrom *BoltStateStore
	incidents  map[string]Incident
	windows    map[string]MaintenanceWindow
	// active maps a key to its unresolved incident's id; latest maps a key
	// to its newest incident's id, the one a flap reopens.
	active map[string]string
	latest map[string]string
}

func (b *incidentBook) reindex() {
	b.active = map[string]string{}
	b.latest = map[string]string{}
	for _, inc := range b.incidents {
		b.indexLocked(inc)
	}
}

func (b *incidentBook) indexLocked(inc Incident) {
	if inc.Active() {
		b.active[inc.Key] = inc.ID
	} else if b.active[inc.Key] == inc.ID {
		delete(b.active, inc.Key)
	}
	if cur, ok := b.incidents[b.latest[inc.Key]]; !ok || cur.ID == inc.ID || !cur.OpenedAt.After(inc.OpenedAt) {
		b.latest[inc.Key] = inc.ID
	}
}

func (b *incidentBook) unindexLocked(inc Incident) {
	if b.active[inc.Key] == inc.ID {
		delete(b.active, inc.Key)
	}
	if b.latest[inc.Key] == inc.ID {
		delete(b.latest, inc.Key)
		// Fall back to the next newest record of the key, if any.
		var best Incident
		found := false
		for _, other := range b.incidents {
			if other.Key != inc.Key || other.ID == inc.ID {
				continue
			}
			if !found || other.OpenedAt.After(best.OpenedAt) {
				best, found = other, true
			}
		}
		if found {
			b.latest[inc.Key] = best.ID
		}
	}
}

// incidentBookLocked returns the book, loading it from bolt the first time
// the hot store is seen. Records written to memory before the hot store was
// enabled are carried into bolt.
func (s *Store) incidentBookLocked() *incidentBook {
	b := &s.incidentBook
	if !b.loaded {
		b.incidents = map[string]Incident{}
		b.windows = map[string]MaintenanceWindow{}
		b.reindex()
		b.loaded = true
	}
	bs := s.runtimeBoltHot
	if bs == nil || b.loadedFrom == bs {
		return b
	}
	incidents, windows, err := bs.LoadIncidents()
	if err != nil {
		// A bucket that cannot be read is a history that starts empty, not a
		// boot failure: alerts must still go out.
		incidents, windows = nil, nil
	}
	carry := incidentWrite{}
	for _, inc := range b.incidents {
		carry.putIncidents = append(carry.putIncidents, inc)
	}
	for _, w := range b.windows {
		carry.putWindows = append(carry.putWindows, w)
	}
	for _, inc := range incidents {
		if _, ok := b.incidents[inc.ID]; !ok {
			b.incidents[inc.ID] = inc
		}
	}
	for _, w := range windows {
		if _, ok := b.windows[w.ID]; !ok {
			b.windows[w.ID] = w
		}
	}
	b.reindex()
	b.loadedFrom = bs
	if !carry.empty() {
		_ = bs.WriteIncidents(carry)
	}
	return b
}

// incidentWrite is one transaction's worth of incident changes.
type incidentWrite struct {
	putIncidents []Incident
	delIncidents []string
	putWindows   []MaintenanceWindow
	delWindows   []string
}

func (w incidentWrite) empty() bool {
	return len(w.putIncidents) == 0 && len(w.delIncidents) == 0 && len(w.putWindows) == 0 && len(w.delWindows) == 0
}

func (s *Store) commitIncidentsLocked(w incidentWrite) error {
	if w.empty() || s.runtimeBoltHot == nil {
		return nil
	}
	return s.runtimeBoltHot.WriteIncidents(w)
}

func (b *incidentBook) applyLocked(w incidentWrite) {
	for _, id := range w.delIncidents {
		if prev, ok := b.incidents[id]; ok {
			delete(b.incidents, id)
			b.unindexLocked(prev)
		}
	}
	for _, inc := range w.putIncidents {
		if prev, ok := b.incidents[inc.ID]; ok {
			b.unindexLocked(prev)
		}
		b.incidents[inc.ID] = inc
		b.indexLocked(inc)
	}
	for _, id := range w.delWindows {
		delete(b.windows, id)
	}
	for _, mw := range w.putWindows {
		b.windows[mw.ID] = mw
	}
}

func cloneIncident(inc Incident) Incident {
	if inc.Escalated != nil {
		m := make(map[string]time.Time, len(inc.Escalated))
		for k, v := range inc.Escalated {
			m[k] = v
		}
		inc.Escalated = m
	}
	inc.OwedOpenRules = slices.Clone(inc.OwedOpenRules)
	return inc
}

func cloneMaintenanceWindow(w MaintenanceWindow) MaintenanceWindow {
	w.NodeIDs = append([]string(nil), w.NodeIDs...)
	w.GroupIDs = append([]string(nil), w.GroupIDs...)
	return w
}

func boundIncidentText(inc Incident) Incident {
	inc.Title, _ = TruncateUTF8(inc.Title, MaxNotifyTitleBytes)
	inc.Detail, _ = TruncateUTF8(inc.Detail, maxIncidentText)
	inc.Line, _ = TruncateUTF8(inc.Line, 512)
	inc.RecoveryTitle, _ = TruncateUTF8(inc.RecoveryTitle, MaxNotifyTitleBytes)
	inc.RecoveryDetail, _ = TruncateUTF8(inc.RecoveryDetail, maxIncidentText)
	inc.RecoveryLine, _ = TruncateUTF8(inc.RecoveryLine, 512)
	inc.Subject, _ = TruncateUTF8(inc.Subject, 256)
	inc.Suppressed, _ = TruncateUTF8(inc.Suppressed, 512)
	return inc
}

// incidentEvictionLocked picks resolved incidents to drop so the book fits
// MaxIncidents after adding rows. Oldest resolved first; never an active
// incident and never a row being written.
func (b *incidentBook) incidentEvictionLocked(adding []Incident) []string {
	added := map[string]bool{}
	newRows := 0
	for _, inc := range adding {
		added[inc.ID] = true
		if _, ok := b.incidents[inc.ID]; !ok {
			newRows++
		}
	}
	excess := len(b.incidents) + newRows - MaxIncidents
	if excess <= 0 {
		return nil
	}
	resolved := make([]Incident, 0, len(b.incidents))
	for _, inc := range b.incidents {
		if !inc.Active() && !added[inc.ID] {
			resolved = append(resolved, inc)
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].ResolvedAt.Before(resolved[j].ResolvedAt) })
	var out []string
	for _, inc := range resolved {
		if excess <= 0 {
			break
		}
		out = append(out, inc.ID)
		excess--
	}
	return out
}

// PutIncidents writes incidents in one transaction, evicting the oldest
// resolved ones when the bound requires it. An incident whose key already
// has another unresolved incident is refused: one problem, one record.
//
// When the bolt write fails the change is still applied in memory and the
// error returned. Memory is what the evaluator reads, so a failing disk
// costs the record at the next restart but never makes the server send the
// same page again on every sweep.
func (s *Store) PutIncidents(rows ...Incident) error {
	if len(rows) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	clean := make([]Incident, 0, len(rows))
	for _, inc := range rows {
		if strings.TrimSpace(inc.ID) == "" || strings.TrimSpace(inc.Key) == "" {
			return errors.New("incident id and key are required")
		}
		if other, ok := b.active[inc.Key]; ok && other != inc.ID && inc.Active() {
			return errors.New("an unresolved incident already exists for " + inc.Key)
		}
		clean = append(clean, cloneIncident(boundIncidentText(inc)))
	}
	w := incidentWrite{putIncidents: clean, delIncidents: b.incidentEvictionLocked(clean)}
	err := s.commitIncidentsLocked(w)
	b.applyLocked(w)
	return err
}

// IncidentsWhere returns the incidents match selects, oldest opened first.
func (s *Store) IncidentsWhere(match func(Incident) bool) []Incident {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	var out []Incident
	for _, inc := range b.incidents {
		if match(inc) {
			out = append(out, cloneIncident(inc))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OpenedAt.Equal(out[j].OpenedAt) {
			return out[i].OpenedAt.Before(out[j].OpenedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// DeleteIncidents removes incidents by id.
func (s *Store) DeleteIncidents(ids ...string) error {
	if len(ids) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	var present []string
	for _, id := range ids {
		if _, ok := b.incidents[id]; ok {
			present = append(present, id)
		}
	}
	w := incidentWrite{delIncidents: present}
	if err := s.commitIncidentsLocked(w); err != nil {
		return err
	}
	b.applyLocked(w)
	return nil
}

// Incident returns one incident by id.
func (s *Store) Incident(id string) (Incident, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	inc, ok := s.incidentBookLocked().incidents[id]
	return cloneIncident(inc), ok
}

// ActiveIncident returns the unresolved incident for a key.
func (s *Store) ActiveIncident(key string) (Incident, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	id, ok := b.active[key]
	if !ok {
		return Incident{}, false
	}
	return cloneIncident(b.incidents[id]), true
}

// LatestIncident returns the newest incident for a key, resolved or not.
func (s *Store) LatestIncident(key string) (Incident, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	id, ok := b.latest[key]
	if !ok {
		return Incident{}, false
	}
	return cloneIncident(b.incidents[id]), true
}

// Incidents returns every incident, newest opened first.
func (s *Store) Incidents() []Incident {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	out := make([]Incident, 0, len(b.incidents))
	for _, inc := range b.incidents {
		out = append(out, cloneIncident(inc))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OpenedAt.Equal(out[j].OpenedAt) {
			return out[i].OpenedAt.After(out[j].OpenedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ActiveIncidents returns the unresolved incidents, newest opened first.
func (s *Store) ActiveIncidents() []Incident {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	out := make([]Incident, 0, len(b.active))
	for _, id := range b.active {
		out = append(out, cloneIncident(b.incidents[id]))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OpenedAt.Equal(out[j].OpenedAt) {
			return out[i].OpenedAt.After(out[j].OpenedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// FlappingIncidents returns resolved incidents still marked flapping; the
// server settles them once they stay resolved long enough.
func (s *Store) FlappingIncidents() []Incident {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	var out []Incident
	for _, inc := range b.incidents {
		if inc.Flapping && !inc.Active() {
			out = append(out, cloneIncident(inc))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// PruneIncidents drops resolved incidents that resolved before cutoff.
func (s *Store) PruneIncidents(cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	var ids []string
	for _, inc := range b.incidents {
		if !inc.Active() && !inc.Flapping && inc.ResolvedAt.Before(cutoff) {
			ids = append(ids, inc.ID)
		}
	}
	w := incidentWrite{delIncidents: ids}
	if err := s.commitIncidentsLocked(w); err != nil {
		return 0, err
	}
	b.applyLocked(w)
	return len(ids), nil
}

// DeleteIncidentsWhere removes every incident match selects, for a deleted
// node or monitor.
func (s *Store) DeleteIncidentsWhere(match func(Incident) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteIncidentsLocked(match)
}

// deleteIncidentsLocked is DeleteIncidentsWhere for a caller holding s.mu;
// the node and monitor delete cascades call it.
func (s *Store) deleteIncidentsLocked(match func(Incident) bool) error {
	b := s.incidentBookLocked()
	var ids []string
	for _, inc := range b.incidents {
		if match(inc) {
			ids = append(ids, inc.ID)
		}
	}
	w := incidentWrite{delIncidents: ids}
	if err := s.commitIncidentsLocked(w); err != nil {
		return err
	}
	b.applyLocked(w)
	return nil
}

// PutMaintenanceWindow stores a window, pruning windows that ended more than
// MaintenanceWindowRetention ago, and refusing one past MaxMaintenanceWindows.
func (s *Store) PutMaintenanceWindow(mw MaintenanceWindow, now time.Time) error {
	if strings.TrimSpace(mw.ID) == "" {
		return errors.New("maintenance window id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	w := incidentWrite{putWindows: []MaintenanceWindow{cloneMaintenanceWindow(mw)}}
	for id, existing := range b.windows {
		if id != mw.ID && now.Sub(existing.EndsAt) > MaintenanceWindowRetention {
			w.delWindows = append(w.delWindows, id)
		}
	}
	if _, ok := b.windows[mw.ID]; !ok && len(b.windows)-len(w.delWindows) >= MaxMaintenanceWindows {
		return errors.New("too many maintenance windows; delete ended ones first")
	}
	if err := s.commitIncidentsLocked(w); err != nil {
		return err
	}
	b.applyLocked(w)
	return nil
}

// DeleteMaintenanceWindow removes a window.
func (s *Store) DeleteMaintenanceWindow(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	if _, ok := b.windows[id]; !ok {
		return nil
	}
	w := incidentWrite{delWindows: []string{id}}
	if err := s.commitIncidentsLocked(w); err != nil {
		return err
	}
	b.applyLocked(w)
	return nil
}

// MaintenanceWindow returns one window by id.
func (s *Store) MaintenanceWindow(id string) (MaintenanceWindow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	mw, ok := s.incidentBookLocked().windows[id]
	return cloneMaintenanceWindow(mw), ok
}

// MaintenanceWindows returns every window, soonest ending first.
func (s *Store) MaintenanceWindows() []MaintenanceWindow {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.incidentBookLocked()
	out := make([]MaintenanceWindow, 0, len(b.windows))
	for _, mw := range b.windows {
		out = append(out, cloneMaintenanceWindow(mw))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].EndsAt.Equal(out[j].EndsAt) {
			return out[i].EndsAt.Before(out[j].EndsAt)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// IncidentsDurable reports whether incidents survive a restart, which they
// do only on the bolt hot store.
func (s *Store) IncidentsDurable() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runtimeBoltHot != nil
}
