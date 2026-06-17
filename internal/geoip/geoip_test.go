package geoip

import (
	"testing"
)

func TestNormalizeParsesIPInfoShape(t *testing.T) {
	out, err := normalize("8.8.8.8", map[string]any{
		"ip":      "8.8.8.8",
		"city":    "Mountain View",
		"region":  "California",
		"country": "US",
		"loc":     "37.3860,-122.0838",
		"org":     "AS15169 Google LLC",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Country != "US" || out.Region != "California" || out.City != "Mountain View" || out.ASN != 15169 || out.ASOrg != "Google LLC" {
		t.Fatalf("bad normalized result: %+v", out)
	}
	if out.Lat != 37.3860 || out.Lon != -122.0838 {
		t.Fatalf("bad coordinates: %+v", out)
	}
}

func TestNormalizeParsesIPAPIShape(t *testing.T) {
	out, err := normalize("1.1.1.1", map[string]any{
		"query":       "1.1.1.1",
		"countryCode": "AU",
		"regionName":  "Queensland",
		"city":        "South Brisbane",
		"lat":         -27.4766,
		"lon":         153.0166,
		"isp":         "Cloudflare",
		"as":          "AS13335 Cloudflare, Inc.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Country != "AU" || out.Region != "Queensland" || out.Provider != "Cloudflare" || out.ASN != 13335 {
		t.Fatalf("bad normalized result: %+v", out)
	}
}

func TestNormalizeRejectsMissingCoordinates(t *testing.T) {
	if _, err := normalize("8.8.8.8", map[string]any{"country": "US"}); err == nil {
		t.Fatal("expected missing coordinates to fail")
	}
}

func TestNewHTTPResolverRequiresExplicitIPTokenAndHTTPS(t *testing.T) {
	if _, err := NewHTTPResolver("https://example.com/geo"); err == nil {
		t.Fatal("expected missing {ip} to fail")
	}
	if _, err := NewHTTPResolver("http://example.com/{ip}"); err == nil {
		t.Fatal("expected non-local http to fail")
	}
}
