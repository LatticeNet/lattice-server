// Package cffake is an in-memory stand-in for the part of the Cloudflare API
// v4 the DDNS provider uses. The ddns and server tests share it so both run
// against the same record semantics: PATCH changes only the fields it is sent,
// PUT replaces the whole record, a name holding a CNAME refuses an A or AAAA
// record with error 81054, and a comment longer than the Free plan's 100
// characters is refused.
//
// It is imported only by tests, so it never reaches the server binary.
package cffake

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// Record is a DNS record as the fake stores and returns it.
type Record struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"`
}

// Write is one create or update the fake received.
type Write struct {
	Method string
	Body   map[string]json.RawMessage
}

// Server is a running fake.
type Server struct {
	*httptest.Server

	mu      sync.Mutex
	zones   []zone
	records []Record
	writes  []Write
	nextID  int
}

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MaxCommentRunes is the Free plan's comment limit.
const MaxCommentRunes = 100

// New starts a fake serving the given zone names. It skips the test when the
// environment has no loopback listener, as the existing ddns tests do.
func New(t testing.TB, zoneNames ...string) *Server {
	t.Helper()
	s := &Server{}
	for i, name := range zoneNames {
		s.zones = append(s.zones, zone{ID: fmt.Sprintf("zone%d", i+1), Name: name})
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("local listener unavailable in this environment: %v", err)
	}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	s.Server.Listener = ln
	s.Server.Start()
	t.Cleanup(s.Server.Close)
	return s
}

// Seed stores a record as if the operator had made it by hand and returns
// its id.
func (s *Server) Seed(r Record) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	r.ID = fmt.Sprintf("rec%d", s.nextID)
	s.records = append(s.records, r)
	return r.ID
}

// Find returns the records at name, optionally of one type.
func (s *Server) Find(name, typ string) []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.matchLocked(name, typ)
}

// Writes returns every create or update received so far.
func (s *Server) Writes() []Write {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Write(nil), s.writes...)
}

func (s *Server) matchLocked(name, typ string) []Record {
	out := []Record{}
	for _, r := range s.records {
		if !strings.EqualFold(r.Name, name) {
			continue
		}
		if typ != "" && !strings.EqualFold(r.Type, typ) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "zones" && r.Method == http.MethodGet:
		ok(w, s.zones)
	case len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == http.MethodGet:
		q := r.URL.Query()
		ok(w, s.matchLocked(q.Get("name"), q.Get("type")))
	case len(parts) == 3 && parts[0] == "zones" && parts[2] == "dns_records" && r.Method == http.MethodPost:
		body, rec, apiErr := decode(r)
		if apiErr != nil {
			fail(w, *apiErr)
			return
		}
		s.writes = append(s.writes, Write{Method: r.Method, Body: body})
		if apiErr := s.conflictLocked(rec); apiErr != nil {
			fail(w, *apiErr)
			return
		}
		s.nextID++
		rec.ID = fmt.Sprintf("rec%d", s.nextID)
		s.records = append(s.records, rec)
		ok(w, rec)
	case len(parts) == 4 && parts[0] == "zones" && parts[2] == "dns_records" && (r.Method == http.MethodPatch || r.Method == http.MethodPut):
		body, rec, apiErr := decode(r)
		if apiErr != nil {
			fail(w, *apiErr)
			return
		}
		s.writes = append(s.writes, Write{Method: r.Method, Body: body})
		for i := range s.records {
			if s.records[i].ID != parts[3] {
				continue
			}
			if r.Method == http.MethodPut {
				rec.ID = s.records[i].ID
				s.records[i] = rec
			} else {
				merge(&s.records[i], body)
			}
			ok(w, s.records[i])
			return
		}
		fail(w, apiError{Code: 81044, Message: "Record does not exist."})
	default:
		http.NotFound(w, r)
	}
}

func decode(r *http.Request) (map[string]json.RawMessage, Record, *apiError) {
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return nil, Record{}, &apiError{Code: 9207, Message: "Request body is invalid."}
	}
	raw, _ := json.Marshal(body)
	var rec Record
	_ = json.Unmarshal(raw, &rec)
	if utf8.RuneCountInString(rec.Comment) > MaxCommentRunes {
		return nil, Record{}, &apiError{Code: 9101, Message: "DNS record comment is too long."}
	}
	if strings.ContainsAny(rec.Comment, "\r\n") {
		return nil, Record{}, &apiError{Code: 9102, Message: "DNS record comment must not contain line breaks."}
	}
	return body, rec, nil
}

// conflictLocked refuses the combinations Cloudflare refuses.
func (s *Server) conflictLocked(rec Record) *apiError {
	for _, have := range s.matchLocked(rec.Name, "") {
		switch {
		case strings.EqualFold(have.Type, "CNAME") && !strings.EqualFold(rec.Type, "CNAME"):
			return &apiError{Code: 81054, Message: "A CNAME record with that host already exists."}
		case strings.EqualFold(rec.Type, "CNAME"):
			return &apiError{Code: 81053, Message: "An A, AAAA, or CNAME record with that host already exists."}
		case strings.EqualFold(have.Type, "NS"):
			return &apiError{Code: 81056, Message: "NS records with that host already exist."}
		}
	}
	return nil
}

func merge(rec *Record, body map[string]json.RawMessage) {
	for key, raw := range body {
		switch key {
		case "type":
			_ = json.Unmarshal(raw, &rec.Type)
		case "name":
			_ = json.Unmarshal(raw, &rec.Name)
		case "content":
			_ = json.Unmarshal(raw, &rec.Content)
		case "ttl":
			_ = json.Unmarshal(raw, &rec.TTL)
		case "proxied":
			_ = json.Unmarshal(raw, &rec.Proxied)
		case "comment":
			_ = json.Unmarshal(raw, &rec.Comment)
		}
	}
}

func ok(w http.ResponseWriter, result any) {
	raw, _ := json.Marshal(result)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []apiError{}, "result": json.RawMessage(raw)})
}

func fail(w http.ResponseWriter, e apiError) {
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []apiError{e}, "result": nil})
}
