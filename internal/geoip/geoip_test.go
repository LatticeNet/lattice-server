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

func TestNormalizeParsesIPWhoIsShape(t *testing.T) {
	out, err := normalize("8.8.8.8", map[string]any{
		"ip":           "8.8.8.8",
		"success":      true,
		"country":      "United States",
		"country_code": "US",
		"region":       "California",
		"city":         "Mountain View",
		"latitude":     37.3860517,
		"longitude":    -122.0838511,
		"connection": map[string]any{
			"asn": float64(15169),
			"org": "Google LLC",
			"isp": "Google LLC",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Country != "US" || out.Region != "California" || out.City != "Mountain View" {
		t.Fatalf("bad normalized result: %+v", out)
	}
	if out.ASN != 15169 || out.ASOrg != "Google LLC" || out.Provider != "Google LLC" {
		t.Fatalf("bad connection fields: %+v", out)
	}
}

func TestNormalizeRejectsProviderFailure(t *testing.T) {
	_, err := normalize("203.0.113.10", map[string]any{
		"success": false,
		"message": "reserved range",
	})
	if err == nil || err.Error() != "reserved range" {
		t.Fatalf("expected provider failure message, got %v", err)
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

func TestNewHTTPResolverAllowsDisableSentinels(t *testing.T) {
	for _, value := range []string{"off", "none", "disabled", "false", "0"} {
		resolver, err := NewHTTPResolver(value)
		if err != nil {
			t.Fatalf("%q should disable without error: %v", value, err)
		}
		if resolver != nil {
			t.Fatalf("%q should return nil resolver", value)
		}
	}
}
