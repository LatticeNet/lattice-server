package geoip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	lookupIPToken = "{ip}"
	maxBodyBytes  = 64 * 1024
)

// Result is a normalized location returned by a GeoIP provider. Coordinates are
// mandatory because the dashboard map cannot place a country-only result.
type Result struct {
	IP       string
	Country  string
	Region   string
	City     string
	Lat      float64
	Lon      float64
	ASN      int
	ASOrg    string
	Provider string
}

type Resolver interface {
	Lookup(ctx context.Context, ip string) (Result, error)
}

type HTTPResolver struct {
	template string
	client   *http.Client
}

func NewHTTPResolver(template string) (*HTTPResolver, error) {
	template = strings.TrimSpace(template)
	if template == "" {
		return nil, nil
	}
	if !strings.Contains(template, lookupIPToken) {
		return nil, errors.New("geoip lookup url must contain {ip}")
	}
	sample := strings.ReplaceAll(template, lookupIPToken, "8.8.8.8")
	parsed, err := url.Parse(sample)
	if err != nil {
		return nil, fmt.Errorf("parse geoip lookup url: %w", err)
	}
	if parsed.Scheme != "https" && !isLocalHTTP(parsed) {
		return nil, errors.New("geoip lookup url must use https, except localhost test endpoints")
	}
	if parsed.Host == "" {
		return nil, errors.New("geoip lookup url must include a host")
	}
	return &HTTPResolver{
		template: template,
		client:   &http.Client{Timeout: 4 * time.Second},
	}, nil
}

func (r *HTTPResolver) Lookup(ctx context.Context, ip string) (Result, error) {
	if r == nil {
		return Result{}, errors.New("geoip resolver is not configured")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return Result{}, fmt.Errorf("invalid ip: %w", err)
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return Result{}, errors.New("ip is not a routable public address")
	}
	lookupURL := strings.ReplaceAll(r.template, lookupIPToken, url.PathEscape(addr.String()))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lookupURL, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := r.client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return Result{}, fmt.Errorf("geoip provider returned %s", res.Status)
	}
	var payload map[string]any
	if err := json.NewDecoder(io.LimitReader(res.Body, maxBodyBytes)).Decode(&payload); err != nil {
		return Result{}, fmt.Errorf("decode geoip response: %w", err)
	}
	out, err := normalize(addr.String(), payload)
	if err != nil {
		return Result{}, err
	}
	return out, nil
}

func normalize(ip string, payload map[string]any) (Result, error) {
	country := strings.ToUpper(firstString(payload, "country_code", "countryCode", "country"))
	if len(country) > 2 {
		country = ""
	}
	lat, latOK := firstFloat(payload, "lat", "latitude")
	lon, lonOK := firstFloat(payload, "lon", "lng", "longitude")
	if (!latOK || !lonOK) && firstString(payload, "loc") != "" {
		parts := strings.Split(firstString(payload, "loc"), ",")
		if len(parts) == 2 {
			if parsedLat, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err == nil {
				if parsedLon, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
					lat, lon = parsedLat, parsedLon
					latOK, lonOK = true, true
				}
			}
		}
	}
	if !latOK || !lonOK {
		return Result{}, errors.New("geoip response did not include coordinates")
	}
	if lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		return Result{}, errors.New("geoip response coordinates are out of range")
	}

	asn, asOrg := parseASN(firstString(payload, "asn", "as"))
	if asn == 0 {
		asn, asOrg = parseASN(firstString(payload, "org"))
	}
	if asOrg == "" {
		asOrg = firstString(payload, "as_org", "asOrg", "org")
	}
	provider := firstString(payload, "provider", "isp", "org")

	return Result{
		IP:       ip,
		Country:  country,
		Region:   firstString(payload, "region", "region_name", "regionName", "subdivision"),
		City:     firstString(payload, "city"),
		Lat:      lat,
		Lon:      lon,
		ASN:      asn,
		ASOrg:    asOrg,
		Provider: provider,
	}, nil
}

func firstString(payload map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := payload[key]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case string:
			if trimmed := strings.TrimSpace(v); trimmed != "" {
				return trimmed
			}
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		case json.Number:
			return v.String()
		}
	}
	return ""
}

func firstFloat(payload map[string]any, keys ...string) (float64, bool) {
	for _, key := range keys {
		value, ok := payload[key]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case float64:
			return v, true
		case string:
			parsed, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
			if err == nil {
				return parsed, true
			}
		case json.Number:
			parsed, err := v.Float64()
			if err == nil {
				return parsed, true
			}
		}
	}
	return 0, false
}

func parseASN(value string) (int, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, ""
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, ""
	}
	prefix := strings.TrimPrefix(strings.ToUpper(fields[0]), "AS")
	asn, err := strconv.Atoi(prefix)
	if err != nil || asn < 0 {
		return 0, value
	}
	org := strings.TrimSpace(strings.TrimPrefix(value, fields[0]))
	return asn, org
}

func isLocalHTTP(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
