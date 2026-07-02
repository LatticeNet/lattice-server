package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-server/internal/outbound"
	"github.com/LatticeNet/lattice-server/internal/store"
)

const defaultAuditHeadShippingInterval = 15 * time.Minute

// AuditHeadShippingOptions configures automated off-box custody for the verified
// audit WAL head. Empty URL disables shipping.
type AuditHeadShippingOptions struct {
	URL         string
	BearerToken string
	Interval    time.Duration
	HTTPClient  *http.Client
}

type auditHeadShipper struct {
	store       *store.Store
	targetURL   string
	bearerToken string
	interval    time.Duration
	client      *http.Client
	logger      *log.Logger
	now         func() time.Time
}

type auditHeadPayload struct {
	Type            string    `json:"type"`
	VerifiedAt      time.Time `json:"verified_at"`
	OK              bool      `json:"ok"`
	Count           int       `json:"count"`
	Head            string    `json:"head"`
	Anchored        bool      `json:"anchored"`
	AnchorCount     int       `json:"anchor_count"`
	AnchorHead      string    `json:"anchor_head"`
	AnchorUpdatedAt time.Time `json:"anchor_updated_at"`
}

func newAuditHeadShipper(st *store.Store, logger *log.Logger, opts AuditHeadShippingOptions) (*auditHeadShipper, error) {
	rawURL := strings.TrimSpace(opts.URL)
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("audit head webhook url is invalid")
	}
	if u.Scheme != "https" {
		return nil, errors.New("audit head webhook url must use https")
	}
	if u.User != nil {
		return nil, errors.New("audit head webhook url must not contain userinfo")
	}
	if u.RawQuery != "" {
		return nil, errors.New("audit head webhook url must not contain a query")
	}
	if u.Fragment != "" {
		return nil, errors.New("audit head webhook url must not contain a fragment")
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = defaultAuditHeadShippingInterval
	}
	client := opts.HTTPClient
	if client == nil {
		client = outbound.NewClient(10 * time.Second)
	}
	if logger == nil {
		logger = log.Default()
	}
	return &auditHeadShipper{
		store:       st,
		targetURL:   u.String(),
		bearerToken: strings.TrimSpace(opts.BearerToken),
		interval:    interval,
		client:      client,
		logger:      logger,
		now:         func() time.Time { return time.Now().UTC() },
	}, nil
}

func (s *auditHeadShipper) start() {
	if s == nil {
		return
	}
	s.logger.Printf("audit head shipping: enabled url=%s interval=%s", s.targetURL, s.interval)
	go func() {
		s.shipAndLog()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		for range ticker.C {
			s.shipAndLog()
		}
	}()
}

func (s *auditHeadShipper) shipAndLog() {
	if err := s.shipOnce(context.Background()); err != nil {
		s.logger.Printf("audit head shipping: %v", err)
	}
}

func (s *auditHeadShipper) shipOnce(ctx context.Context) error {
	if s == nil {
		return errors.New("audit head shipper is nil")
	}
	res, enabled, err := s.store.AuditWALVerify()
	if !enabled {
		return errors.New("audit WAL disabled")
	}
	if err != nil {
		return fmt.Errorf("audit WAL verify: %w", err)
	}
	if res.Anchor == nil {
		return errors.New("audit WAL anchor missing")
	}
	if res.Anchor.Count != res.Count || res.Anchor.Head != res.Head || res.Anchor.Pending != nil {
		return fmt.Errorf("audit WAL anchor is not committed at verified head")
	}
	payload := auditHeadPayload{
		Type:            "lattice.audit_head.v1",
		VerifiedAt:      s.now(),
		OK:              true,
		Count:           res.Count,
		Head:            res.Head,
		Anchored:        true,
		AnchorCount:     res.Anchor.Count,
		AnchorHead:      res.Anchor.Head,
		AnchorUpdatedAt: res.Anchor.UpdatedAt,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.targetURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "lattice-server/audit-head-shipper")
	if s.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.bearerToken)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("audit head webhook status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}
