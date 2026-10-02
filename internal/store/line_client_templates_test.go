package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
)

func lineTemplateFixture(node, hash, sni string) LineClientTemplate {
	return LineClientTemplate{LineHashID: hash, NodeID: node, Tag: "vless-" + hash, Protocol: "vless", Host: "203.0.113.5", Port: 443,
		Params: map[string]string{"security": "reality", "sni": sni, "pbk": "pbk-" + hash}}
}

// Templates are written when a line's configuration changes and at no other
// time. A hundred identical syncs, which is a little under two hours of the
// server's sync timer, cost nothing after the first, and a template that did
// not change keeps the time it last changed.
func TestLineClientTemplatesWriteOnlyOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := OpenWithCipher(path, testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	nodeA := []LineClientTemplate{lineTemplateFixture("node-a", "line_a1", "a.example.com"), lineTemplateFixture("node-a", "line_a2", "a.example.com")}
	nodeB := []LineClientTemplate{lineTemplateFixture("node-b", "line_b1", "b.example.com")}
	before := s.testPersistCalls
	if written, err := s.SyncLineClientTemplates(map[string][]LineClientTemplate{"node-a": nodeA, "node-b": nodeB}, t0); err != nil || !written {
		t.Fatalf("first sync: written=%v err=%v", written, err)
	}
	for i := 1; i <= 100; i++ {
		if written, err := s.SyncLineClientTemplates(map[string][]LineClientTemplate{"node-a": nodeA, "node-b": nodeB}, t0.Add(time.Duration(i)*time.Minute)); err != nil || written {
			t.Fatalf("identical sync %d: written=%v err=%v", i, written, err)
		}
	}
	if calls := s.testPersistCalls - before; calls != 1 {
		t.Fatalf("101 syncs, one change: %d writes, want 1", calls)
	}

	changed := lineTemplateFixture("node-a", "line_a1", "new.example.com")
	t1 := t0.Add(3 * time.Hour)
	if written, err := s.SyncLineClientTemplates(map[string][]LineClientTemplate{"node-a": {changed}}, t1); err != nil || !written {
		t.Fatalf("changed sync: written=%v err=%v", written, err)
	}
	if got, ok := s.LineClientTemplate("line_a1"); !ok || got.Params["sni"] != "new.example.com" || !got.UpdatedAt.Equal(t1) {
		t.Fatalf("changed template = %+v", got)
	}
	if _, ok := s.LineClientTemplate("line_a2"); ok {
		t.Fatal("a line the node no longer reports must lose its template")
	}
	if got, ok := s.LineClientTemplate("line_b1"); !ok || !got.UpdatedAt.Equal(t0) {
		t.Fatalf("a node left out of the sync must keep its templates untouched: %+v ok=%v", got, ok)
	}

	// A template handed out is a copy.
	got, _ := s.LineClientTemplate("line_b1")
	got.Params["sni"] = "tampered"
	if again, _ := s.LineClientTemplate("line_b1"); again.Params["sni"] != "b.example.com" {
		t.Fatal("LineClientTemplate handed out the store's own map")
	}

	cipher := s.cipher
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenWithCipher(path, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if all := reopened.LineClientTemplates(); len(all) != 2 || all[0].LineHashID != "line_a1" || all[1].LineHashID != "line_b1" {
		t.Fatalf("templates after reopen: %+v", all)
	}
}

// A template the store cannot keep is refused with the whole sync, so a bad
// builder cannot leave half a node's set behind.
func TestLineClientTemplatesRefuseABadRecord(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	good := lineTemplateFixture("node-a", "line_a1", "a.example.com")
	for name, edit := range map[string]func(*LineClientTemplate){
		"shadowsocks":       func(t *LineClientTemplate) { t.Protocol = "shadowsocks" },
		"no port":           func(t *LineClientTemplate) { t.Port = 0 },
		"host with a path":  func(t *LineClientTemplate) { t.Host = "evil/x" },
		"control character": func(t *LineClientTemplate) { t.Params["path"] = "/x\n" },
		"wrong node":        func(t *LineClientTemplate) { t.NodeID = "node-b" },
	} {
		t.Run(name, func(tt *testing.T) {
			bad := lineTemplateFixture("node-a", "line_a2", "a.example.com")
			edit(&bad)
			if _, err := s.SyncLineClientTemplates(map[string][]LineClientTemplate{"node-a": {good, bad}}, time.Now()); err == nil {
				tt.Fatal("want a refusal")
			}
			if len(s.LineClientTemplates()) != 0 {
				tt.Fatal("a refused sync must keep nothing")
			}
		})
	}
	if _, err := s.SyncLineClientTemplates(map[string][]LineClientTemplate{"node-a": {good, good}}, time.Now()); err == nil {
		t.Fatal("a line listed twice must be refused")
	}
}

func TestLineClientTemplatesRoundTripThroughBoltState(t *testing.T) {
	bs, err := OpenBoltState(filepath.Join(t.TempDir(), "state.db"), testCipher(t))
	if err != nil {
		t.Fatal(err)
	}
	defer bs.Close()
	st := emptyState()
	st.LineClientTemplates["line_a1"] = lineTemplateFixture("node-a", "line_a1", "a.example.com")
	if err := bs.ImportState(st); err != nil {
		t.Fatal(err)
	}
	out, err := bs.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if got := out.LineClientTemplates["line_a1"]; got.Params["sni"] != "a.example.com" || got.Port != 443 {
		t.Fatalf("bolt round trip: %+v", out.LineClientTemplates)
	}
}

// Deleting a node removes its templates, which nothing else would: they are
// kept for silent nodes on purpose.
func TestLineClientTemplatesGoWithTheNode(t *testing.T) {
	s, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"node-a", "node-b"} {
		if err := s.UpsertNode(model.Node{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.SyncLineClientTemplates(map[string][]LineClientTemplate{
		"node-a": {lineTemplateFixture("node-a", "line_a1", "a.example.com")},
		"node-b": {lineTemplateFixture("node-b", "line_b1", "b.example.com")},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.DeleteNode("node-a"); err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	if all := s.LineClientTemplates(); len(all) != 1 || all[0].NodeID != "node-b" {
		t.Fatalf("after deleting node-a: %+v", all)
	}
}
