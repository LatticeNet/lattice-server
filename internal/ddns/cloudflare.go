package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const cloudflareDefaultBase = "https://api.cloudflare.com/client/v4"

// Cloudflare sets A/AAAA records through the Cloudflare API v4 using an API
// token. The token needs Zone:Read + DNS:Edit on the target zones.
type Cloudflare struct {
	Token   string
	BaseURL string // defaults to cloudflareDefaultBase
	Client  *http.Client

	zones []cfZone // cached zone list (id+name)
}

func (c *Cloudflare) Kind() string { return "cloudflare" }

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment"` // Cloudflare sends null for none
}

// cfWrite is the body of a create or an update. Updates are PATCH, which
// changes only the fields present, so a nil Comment leaves the record's
// comment alone and anything else the operator set by hand (tags, record
// settings) survives. Proxied is still sent explicitly on every write.
type cfWrite struct {
	Type    string  `json:"type"`
	Name    string  `json:"name"`
	Content string  `json:"content"`
	TTL     int     `json:"ttl"`
	Proxied *bool   `json:"proxied,omitempty"`
	Comment *string `json:"comment,omitempty"`
}

type cfEnvelope struct {
	Success bool            `json:"success"`
	Errors  json.RawMessage `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfErrorItem struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// cfAPIError is a request Cloudflare answered with success=false.
type cfAPIError struct {
	Status int
	Items  []cfErrorItem
	raw    string
}

func (e *cfAPIError) Error() string {
	return fmt.Sprintf("cloudflare: api error (status %d): %s", e.Status, e.raw)
}

// hostTaken reports whether Cloudflare refused a write because the name
// already holds a record the new one cannot share it with: 81053 and 81054
// for the CNAME rules, 81056 for a delegated (NS) name, and the same
// sentence under whatever code a future API version gives it.
func (e *cfAPIError) hostTaken() bool {
	for _, item := range e.Items {
		switch item.Code {
		case 81053, 81054, 81056:
			return true
		}
		msg := strings.ToLower(item.Message)
		if strings.Contains(msg, "with that host already exist") {
			return true
		}
	}
	return false
}

// ConflictError is Cloudflare refusing a record because its name already
// holds one it cannot coexist with, most often a CNAME. Its message is meant
// to be read by the operator as it stands.
type ConflictError struct {
	Name     string
	Type     string // the type Lattice tried to write
	Existing []ExistingRecord
	Cause    error
}

func (e *ConflictError) Error() string {
	if blocker, ok := BlockingRecord(e.Existing); ok {
		return ConflictSentence(e.Name, blocker)
	}
	return fmt.Sprintf("%s already has a record that Cloudflare will not let %s %s record share (%v). Remove it in Cloudflare or use another name.",
		e.Name, article(e.Type), e.Type, e.Cause)
}

func (e *ConflictError) Unwrap() error { return e.Cause }

// BlockingRecord picks, among the records already at a name, the one that
// stops Lattice from writing its A or AAAA record there: a CNAME, which may
// not share its name with anything, or an NS record, which hands the name to
// another zone.
func BlockingRecord(existing []ExistingRecord) (ExistingRecord, bool) {
	for _, rec := range existing {
		if strings.EqualFold(rec.Type, "CNAME") || strings.EqualFold(rec.Type, "NS") {
			return rec, true
		}
	}
	return ExistingRecord{}, false
}

// ConflictSentence explains, for the operator, the record that blocks name.
// The run error and the save-time warning both use it, so they say the same
// thing.
func ConflictSentence(name string, blocker ExistingRecord) string {
	typ := strings.ToUpper(blocker.Type)
	return fmt.Sprintf("%s already has %s %s record pointing to %s; a name cannot hold both. Remove that record in Cloudflare or use another name.",
		name, article(typ), typ, strings.TrimSuffix(blocker.Content, "."))
}

// article picks "a" or "an" for a record type read letter by letter: an A,
// an AAAA, an NS, an MX, but a CNAME, a TXT.
func article(recordType string) string {
	if recordType != "" && strings.ContainsRune("AEFHILMNORSX", rune(strings.ToUpper(recordType)[0])) {
		return "an"
	}
	return "a"
}

func (c *Cloudflare) base() string {
	if c.BaseURL != "" {
		return strings.TrimRight(c.BaseURL, "/")
	}
	return cloudflareDefaultBase
}

func (c *Cloudflare) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return defaultClient()
}

func (c *Cloudflare) SetRecord(ctx context.Context, r Record) error {
	zone, err := c.zoneFor(ctx, r.Name)
	if err != nil {
		return err
	}
	existing, err := c.findRecord(ctx, zone.ID, r.Type, r.Name)
	if err != nil {
		return err
	}
	if existing == nil {
		unproxied := false
		payload := cfWrite{Type: r.Type, Name: r.Name, Content: r.IP, TTL: r.TTL, Proxied: &unproxied}
		if r.Comment != nil {
			comment := r.Comment.render(r, "")
			payload.Comment = &comment
		}
		err := c.do(ctx, http.MethodPost, fmt.Sprintf("/zones/%s/dns_records", zone.ID), payload, nil)
		return c.explainConflict(ctx, zone.ID, r, err)
	}

	addressChanged := existing.Content != r.IP
	// Proxying is the operator's call, made in Cloudflare. A record they
	// orange-clouded stays proxied, and Cloudflare keeps proxied records on
	// automatic TTL, which the API spells 1.
	proxied := existing.Proxied
	payload := cfWrite{Type: r.Type, Name: r.Name, Content: r.IP, TTL: r.TTL, Proxied: &proxied}
	if proxied {
		payload.TTL = 1
	}
	commentChanged := false
	if r.Comment != nil {
		comment := r.Comment.render(r, existing.Content)
		if comment != existing.Comment && (addressChanged || r.Comment.Refresh) {
			payload.Comment = &comment
			commentChanged = true
		}
	}
	if !addressChanged && !commentChanged {
		return nil // already correct, no-op
	}
	err = c.do(ctx, http.MethodPatch,
		fmt.Sprintf("/zones/%s/dns_records/%s", zone.ID, existing.ID), payload, nil)
	return c.explainConflict(ctx, zone.ID, r, err)
}

// explainConflict turns Cloudflare's "record with that host already exists"
// into a sentence naming the record in the way, looked up on the spot. Any
// other error passes through unchanged.
func (c *Cloudflare) explainConflict(ctx context.Context, zoneID string, r Record, err error) error {
	var apiErr *cfAPIError
	if err == nil || !errors.As(err, &apiErr) || !apiErr.hostTaken() {
		return err
	}
	existing, lookupErr := c.recordsAt(ctx, zoneID, r.Name)
	if lookupErr != nil {
		existing = nil
	}
	return &ConflictError{Name: r.Name, Type: r.Type, Existing: existing, Cause: err}
}

// RecordsAt lists every record at name, whatever its type.
func (c *Cloudflare) RecordsAt(ctx context.Context, name string) ([]ExistingRecord, error) {
	zone, err := c.zoneFor(ctx, name)
	if err != nil {
		return nil, err
	}
	return c.recordsAt(ctx, zone.ID, name)
}

func (c *Cloudflare) recordsAt(ctx context.Context, zoneID, name string) ([]ExistingRecord, error) {
	var recs []cfRecord
	q := url.Values{"name": {name}}
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/zones/%s/dns_records?%s", zoneID, q.Encode()), nil, &recs); err != nil {
		return nil, err
	}
	out := make([]ExistingRecord, 0, len(recs))
	for _, rec := range recs {
		out = append(out, ExistingRecord{Type: rec.Type, Content: rec.Content, Proxied: rec.Proxied, Comment: rec.Comment})
	}
	return out, nil
}

// zoneFor finds the longest zone whose name is a suffix of the record name.
func (c *Cloudflare) zoneFor(ctx context.Context, name string) (cfZone, error) {
	if c.zones == nil {
		if err := c.loadZones(ctx); err != nil {
			return cfZone{}, err
		}
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	var best cfZone
	for _, z := range c.zones {
		zn := strings.ToLower(z.Name)
		if name == zn || strings.HasSuffix(name, "."+zn) {
			if len(zn) > len(best.Name) {
				best = z
			}
		}
	}
	if best.ID == "" {
		return cfZone{}, fmt.Errorf("no cloudflare zone found for %q", name)
	}
	return best, nil
}

func (c *Cloudflare) loadZones(ctx context.Context) error {
	var zones []cfZone
	if err := c.do(ctx, http.MethodGet, "/zones?per_page=50", nil, &zones); err != nil {
		return err
	}
	c.zones = zones
	return nil
}

func (c *Cloudflare) findRecord(ctx context.Context, zoneID, recType, name string) (*cfRecord, error) {
	var recs []cfRecord
	path := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s", zoneID, recType, name)
	if err := c.do(ctx, http.MethodGet, path, nil, &recs); err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, nil
	}
	return &recs[0], nil
}

// do performs an authenticated API call, unwraps the Cloudflare envelope, and
// decodes result into out when provided.
func (c *Cloudflare) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env cfEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("cloudflare: status %d, undecodable body", resp.StatusCode)
	}
	if !env.Success {
		apiErr := &cfAPIError{Status: resp.StatusCode, raw: string(env.Errors)}
		_ = json.Unmarshal(env.Errors, &apiErr.Items)
		return apiErr
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}
