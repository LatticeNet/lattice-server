package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
}

type cfEnvelope struct {
	Success bool            `json:"success"`
	Errors  json.RawMessage `json:"errors"`
	Result  json.RawMessage `json:"result"`
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
	payload := cfRecord{Type: r.Type, Name: r.Name, Content: r.IP, TTL: r.TTL, Proxied: false}
	if existing != nil {
		if existing.Content == r.IP {
			return nil // already correct, no-op
		}
		return c.do(ctx, http.MethodPut,
			fmt.Sprintf("/zones/%s/dns_records/%s", zone.ID, existing.ID), payload, nil)
	}
	return c.do(ctx, http.MethodPost,
		fmt.Sprintf("/zones/%s/dns_records", zone.ID), payload, nil)
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
		return fmt.Errorf("cloudflare: api error (status %d): %s", resp.StatusCode, string(env.Errors))
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}
