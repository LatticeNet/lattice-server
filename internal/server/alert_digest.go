package server

import (
	"fmt"
	"sort"
	"strings"
	"sync"
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
}

func (s *Server) queueAlertDigest(eventType string, l alertDigestLine) {
	d := &s.alertDigest
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == nil {
		d.pending = map[string][]alertDigestLine{}
	}
	d.pending[eventType] = append(d.pending[eventType], l)
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
	for _, kind := range kinds {
		lines := pending[kind]
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
