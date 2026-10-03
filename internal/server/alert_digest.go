package server

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/store"
)

// alertDigest batches typed alerts that are decided one node at a time and
// sends each kind as one message per liveness sweep tick.
//
// service.down and service.recovered are decided when a node's probe arrives,
// and monitor transitions when a node's result arrives, so a fleet-wide
// sing-box roll that breaks twenty cores used to page twenty times, and an
// all-nodes monitor against a target that went down paged once per node. The
// emitters now queue a line and the sweep sends one message per event type:
// a single line keeps its own title and body, several become a digest that
// names every node. node.offline and node.online already work this way
// (nodeOfflineMessage); this is the same rule for the alerts that do not
// originate in the sweep.
//
// Event types do not change, so operator rules and templates route exactly as
// before. A queued line waits at most one sweep interval (20 s), on top of
// holds that are already 90 s or two probe intervals long.
//
// The decision behind a queued line is already on disk (the sing-box episode,
// the monitor history), so a line dropped by a restart is a page that is never
// sent. Each line is therefore stored as it is queued (store digest lines) and
// removed after the flush has put its message in the notification outbox; a
// process killed in between finds the line at the next start and sends it
// then. A kill after the outbox write and before the removal sends the
// message twice, which is the side an alert should err on. Server.Close
// flushes what is queued, so a restart through SIGTERM sends it at once.
type alertDigest struct {
	mu      sync.Mutex
	pending map[string][]alertDigestLine
}

// alertDigestLine is one node's share of a message: what it would have sent
// alone, and the line it contributes to a digest.
type alertDigestLine struct {
	sortKey     string
	title, body string
	line        string
	// key is the stored line's key; empty when the store refused it.
	key string
}

func (s *Server) queueAlertDigest(eventType string, l alertDigestLine) {
	now := s.now()
	key := store.NewNotifyDigestKey(now, id.New("ndq"))
	if err := s.store.QueueNotifyDigestLine(store.NotifyDigestLine{
		Key: key, EventType: eventType, SortKey: l.sortKey,
		Title: l.title, Body: l.body, Line: l.line, QueuedAt: now,
	}); err != nil {
		s.logger.Printf("alert digest: store queued line: %v", err)
	} else {
		l.key = key
	}
	d := &s.alertDigest
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == nil {
		d.pending = map[string][]alertDigestLine{}
	}
	d.pending[eventType] = append(d.pending[eventType], l)
}

// restoreAlertDigest takes back the lines a previous process stored and never
// flushed. The next sweep (or Close) sends them.
func (s *Server) restoreAlertDigest() {
	lines := s.store.NotifyDigestLines()
	if len(lines) == 0 {
		return
	}
	d := &s.alertDigest
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == nil {
		d.pending = map[string][]alertDigestLine{}
	}
	for _, l := range lines {
		d.pending[l.EventType] = append(d.pending[l.EventType], alertDigestLine{
			sortKey: l.SortKey, title: l.Title, body: l.Body, line: l.Line, key: l.Key,
		})
	}
	s.logger.Printf("alert digest: %d queued line(s) restored from the previous run", len(lines))
}

// flushAlertDigests sends what was queued since the previous flush, one
// message per event type, in a stable order.
func (s *Server) flushAlertDigests() {
	d := &s.alertDigest
	d.mu.Lock()
	pending := d.pending
	d.pending = nil
	d.mu.Unlock()
	if len(pending) == 0 {
		return
	}
	kinds := make([]string, 0, len(pending))
	for kind := range pending {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	var flushed []string
	for _, kind := range kinds {
		lines := pending[kind]
		for _, l := range lines {
			if l.key != "" {
				flushed = append(flushed, l.key)
			}
		}
		if len(lines) == 1 {
			s.emitNotifyTyped(kind, lines[0].title, lines[0].body)
			continue
		}
		sort.SliceStable(lines, func(i, j int) bool { return lines[i].sortKey < lines[j].sortKey })
		body := make([]string, len(lines))
		for i, l := range lines {
			body[i] = l.line
		}
		s.emitNotifyTyped(kind, alertDigestTitle(kind, len(lines)), strings.Join(body, "\n"))
	}
	if err := s.store.RemoveNotifyDigestLines(flushed); err != nil {
		s.logger.Printf("alert digest: remove flushed lines: %v", err)
	}
}

func alertDigestTitle(kind string, n int) string {
	switch kind {
	case EventServiceDown:
		return fmt.Sprintf("sing-box down digest: %d nodes", n)
	case EventServiceRecovered:
		return fmt.Sprintf("sing-box recovered digest: %d nodes", n)
	case EventMonitorDown:
		return fmt.Sprintf("Monitor down digest: %d", n)
	case EventMonitorRecovered:
		return fmt.Sprintf("Monitor recovered digest: %d", n)
	default:
		return fmt.Sprintf("%s digest: %d", kind, n)
	}
}

// notifyInflight counts notification deliveries still running so shutdown can
// wait for them. It is not a sync.WaitGroup because a sweep may start a
// delivery from zero while Close is waiting, which a WaitGroup forbids.
type notifyInflight struct {
	mu   sync.Mutex
	n    int
	idle chan struct{}
}

func (f *notifyInflight) begin() {
	f.mu.Lock()
	f.n++
	f.mu.Unlock()
}

func (f *notifyInflight) end() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n--
	if f.n == 0 && f.idle != nil {
		close(f.idle)
		f.idle = nil
	}
}

// wait returns 0 once no delivery is running, or the number still running
// when ctx ends first.
func (f *notifyInflight) wait(ctx context.Context) int {
	f.mu.Lock()
	if f.n == 0 {
		f.mu.Unlock()
		return 0
	}
	if f.idle == nil {
		f.idle = make(chan struct{})
	}
	idle := f.idle
	f.mu.Unlock()
	select {
	case <-idle:
		return 0
	case <-ctx.Done():
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.n
	}
}
