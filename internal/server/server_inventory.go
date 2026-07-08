package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
	"github.com/LatticeNet/lattice-server/internal/rbac"
)

const (
	maxMachineShort = 128
	maxMachineURL   = 4096
	maxMachineNotes = 2048
)

type machineView struct {
	ID               string               `json:"id,omitempty"`
	NodeID           string               `json:"node_id"`
	NodeName         string               `json:"node_name,omitempty"`
	Label            string               `json:"label,omitempty"`
	Online           bool                 `json:"online"`
	HostFacts        model.HostFacts      `json:"host_facts"`
	Vendor           string               `json:"vendor,omitempty"`
	VendorProfile    *model.MachineVendor `json:"vendor_profile,omitempty"`
	Region           string               `json:"region,omitempty"`
	HasConsoleURL    bool                 `json:"has_console_url"`
	HasDetailURL     bool                 `json:"has_detail_url"`
	Notes            string               `json:"notes,omitempty"`
	PriceCents       int64                `json:"price_cents,omitempty"`
	Currency         string               `json:"currency,omitempty"`
	PurchasedAt      *time.Time           `json:"purchased_at,omitempty"`
	RenewalCycle     string               `json:"renewal_cycle,omitempty"`
	CycleDays        int                  `json:"cycle_days,omitempty"`
	NextRenewal      *time.Time           `json:"next_renewal,omitempty"`
	DaysUntilRenewal *int                 `json:"days_until_renewal,omitempty"`
	AutoRoll         bool                 `json:"auto_roll"`
	RemindDaysBefore []int                `json:"remind_days_before,omitempty"`
	RemindersEnabled bool                 `json:"reminders_enabled"`
	CreatedAt        time.Time            `json:"created_at,omitempty"`
	UpdatedAt        time.Time            `json:"updated_at,omitempty"`
}

type machineProfileRequest struct {
	ID               string    `json:"id"`
	NodeID           string    `json:"node_id"`
	Label            string    `json:"label"`
	Vendor           string    `json:"vendor"`
	ConsoleURL       string    `json:"console_url"`
	DetailURL        string    `json:"detail_url"`
	ClearConsoleURL  bool      `json:"clear_console_url"`
	ClearDetailURL   bool      `json:"clear_detail_url"`
	Region           string    `json:"region"`
	Notes            string    `json:"notes"`
	PriceCents       int64     `json:"price_cents"`
	Currency         string    `json:"currency"`
	PurchasedAt      time.Time `json:"purchased_at"`
	RenewalCycle     string    `json:"renewal_cycle"`
	CycleDays        int       `json:"cycle_days"`
	NextRenewal      time.Time `json:"next_renewal"`
	AutoRoll         bool      `json:"auto_roll"`
	RemindDaysBefore []int     `json:"remind_days_before"`
	RemindersEnabled bool      `json:"reminders_enabled"`
	LastRemindedKey  string    `json:"last_reminded_key"`
	fields           map[string]bool
}

type machineVendorRequest struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	LogoURL     string `json:"logo_url"`
	Description string `json:"description"`
}

var machineProfileRequestFields = map[string]bool{
	"id":                 true,
	"node_id":            true,
	"label":              true,
	"vendor":             true,
	"console_url":        true,
	"detail_url":         true,
	"clear_console_url":  true,
	"clear_detail_url":   true,
	"region":             true,
	"notes":              true,
	"price_cents":        true,
	"currency":           true,
	"purchased_at":       true,
	"renewal_cycle":      true,
	"cycle_days":         true,
	"next_renewal":       true,
	"auto_roll":          true,
	"remind_days_before": true,
	"reminders_enabled":  true,
	"last_reminded_key":  true,
}

func (r *machineProfileRequest) UnmarshalJSON(data []byte) error {
	type wire machineProfileRequest
	var out wire
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = machineProfileRequest(out)
	r.fields = make(map[string]bool, len(raw))
	for field := range raw {
		if !machineProfileRequestFields[field] {
			return fmt.Errorf("json: unknown field %q", field)
		}
		r.fields[field] = true
	}
	return nil
}

func (r machineProfileRequest) has(field string) bool {
	return r.fields == nil || r.fields[field]
}

type renewalReminderFire struct {
	MachineID   string `json:"machine_id"`
	NodeID      string `json:"node_id"`
	NodeName    string `json:"node_name,omitempty"`
	OffsetDays  int    `json:"offset_days"`
	NextRenewal string `json:"next_renewal"`
}

func (s *Server) handleMachines(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "inventory:read") {
			return
		}
		writeJSON(w, http.StatusOK, s.machineViewsForPrincipal(p))
	case http.MethodPost:
		var req machineProfileRequest
		if !decodeClientJSON(w, r, &req) {
			return
		}
		req.ID = ""
		profile, err := s.machineProfileFromRequest(req, model.MachineProfile{}, true)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if _, ok := s.store.Node(profile.NodeID); !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		if !s.requireNodeScope(w, p, "inventory:admin", profile.NodeID) {
			return
		}
		if existing, ok := s.store.MachineProfileForNode(profile.NodeID); ok {
			writeError(w, http.StatusBadRequest, fmt.Errorf("machine profile already exists for node %s (%s)", profile.NodeID, existing.ID))
			return
		}
		profile.ID = id.New("machine")
		if err := s.store.UpsertMachineProfile(profile); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: profile.NodeID,
			Action: "inventory.create",
			Scope:  "inventory:admin",
			Metadata: map[string]string{
				"machine_id": profile.ID,
			},
		})
		created, _ := s.store.MachineProfile(profile.ID)
		node, _ := s.store.Node(profile.NodeID)
		writeJSON(w, http.StatusOK, toMachineView(node, created, s.machineVendorMap(), s.now()))
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleMachineVendors(w http.ResponseWriter, r *http.Request, p principal) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireScope(w, p, "inventory:read") {
			return
		}
		writeJSON(w, http.StatusOK, map[string][]model.MachineVendor{"vendors": s.machineVendorsForPrincipal(p)})
	case http.MethodPost:
		var req machineVendorRequest
		if !decodeClientJSON(w, r, &req) {
			return
		}
		if !s.requireScope(w, p, "inventory:admin") {
			return
		}
		vendor, err := s.machineVendorFromRequest(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.store.UpsertMachineVendor(vendor); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		stored, _ := s.store.MachineVendor(vendor.ID)
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			Action: "inventory.vendor.upsert",
			Scope:  "inventory:admin",
			Metadata: map[string]string{
				"vendor_id": vendor.ID,
				"name":      vendor.Name,
			},
		})
		writeJSON(w, http.StatusOK, map[string]model.MachineVendor{"vendor": stored})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (s *Server) handleDeleteMachineVendor(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	if req.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if err := s.store.DeleteMachineVendor(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "inventory.vendor.delete", Scope: "inventory:admin", Metadata: map[string]string{"vendor_id": req.ID}})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMachineUpdate(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req machineProfileRequest
	if !decodeClientJSON(w, r, &req) {
		return
	}
	existing, ok := s.store.MachineProfile(strings.TrimSpace(req.ID))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("machine profile not found"))
		return
	}
	if !s.requireNodeScope(w, p, "inventory:admin", existing.NodeID) {
		return
	}
	updated, err := s.machineProfileFromRequest(req, existing, false)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if updated.NodeID != existing.NodeID {
		if !s.requireNodeScope(w, p, "inventory:admin", updated.NodeID) {
			return
		}
		if _, ok := s.store.Node(updated.NodeID); !ok {
			writeError(w, http.StatusNotFound, errors.New("node not found"))
			return
		}
		if other, ok := s.store.MachineProfileForNode(updated.NodeID); ok && other.ID != existing.ID {
			writeError(w, http.StatusBadRequest, fmt.Errorf("machine profile already exists for node %s (%s)", updated.NodeID, other.ID))
			return
		}
	}
	if err := s.store.UpsertMachineProfile(updated); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: updated.NodeID,
		Action: "inventory.update",
		Scope:  "inventory:admin",
		Metadata: map[string]string{
			"machine_id": updated.ID,
		},
	})
	stored, _ := s.store.MachineProfile(updated.ID)
	node, _ := s.store.Node(stored.NodeID)
	writeJSON(w, http.StatusOK, toMachineView(node, stored, s.machineVendorMap(), s.now()))
}

func (s *Server) handleDeleteMachine(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	nodeID := ""
	if profile, ok := s.store.MachineProfile(req.ID); ok {
		nodeID = profile.NodeID
		if !s.requireNodeScope(w, p, "inventory:admin", profile.NodeID) {
			return
		}
	}
	if err := s.store.DeleteMachineProfile(req.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: nodeID,
		Action: "inventory.delete",
		Scope:  "inventory:admin",
		Metadata: map[string]string{
			"machine_id": req.ID,
		},
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMachineRenew(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID          string    `json:"id"`
		NextRenewal time.Time `json:"next_renewal"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	profile, ok := s.store.MachineProfile(strings.TrimSpace(req.ID))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("machine profile not found"))
		return
	}
	if !s.requireNodeScope(w, p, "inventory:admin", profile.NodeID) {
		return
	}
	next := req.NextRenewal
	if next.IsZero() {
		if !profile.AutoRoll {
			writeError(w, http.StatusBadRequest, errors.New("next_renewal is required when auto_roll is disabled"))
			return
		}
		var err error
		next, err = advanceRenewal(profile.NextRenewal, profile.RenewalCycle, profile.CycleDays)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
	}
	profile.NextRenewal = dateOnlyUTC(next)
	profile.LastRemindedKey = ""
	if err := s.store.UpsertMachineProfile(profile); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{
		ID:     id.New("audit"),
		NodeID: profile.NodeID,
		Action: "inventory.renew",
		Scope:  "inventory:admin",
		Metadata: map[string]string{
			"machine_id":   profile.ID,
			"next_renewal": profile.NextRenewal.Format("2006-01-02"),
		},
	})
	stored, _ := s.store.MachineProfile(profile.ID)
	node, _ := s.store.Node(stored.NodeID)
	writeJSON(w, http.StatusOK, toMachineView(node, stored, s.machineVendorMap(), s.now()))
}

func (s *Server) handleMachineRemindersRun(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if !decodeClientJSON(w, r, &req) {
			return
		}
	}
	req.ID = strings.TrimSpace(req.ID)
	fired, err := s.evaluateMachineReminders(s.now(), req.ID, func(profile model.MachineProfile) bool {
		return rbac.Allows(p.Principal, "inventory:admin", profile.NodeID)
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	for _, fire := range fired {
		s.recordPrincipalAudit(p, model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: fire.NodeID,
			Action: "inventory.reminder.manual",
			Scope:  "inventory:admin",
			Metadata: map[string]string{
				"machine_id":   fire.MachineID,
				"offset_days":  strconv.Itoa(fire.OffsetDays),
				"next_renewal": fire.NextRenewal,
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string][]renewalReminderFire{"fired": fired})
}

func (s *Server) handleMachineLinkReveal(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID          string `json:"id"`
		Kind        string `json:"kind"`
		StepUpGrant string `json:"step_up_grant"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	req.ID = strings.TrimSpace(req.ID)
	req.Kind = strings.TrimSpace(req.Kind)
	profile, ok := s.store.MachineProfile(req.ID)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("machine profile not found"))
		return
	}
	if !s.requireNodeScope(w, p, "inventory:admin", profile.NodeID) {
		return
	}
	if !s.requireStepUpGrant(w, p, strings.TrimSpace(req.StepUpGrant), "inventory.link.reveal") {
		return
	}
	link := ""
	switch req.Kind {
	case "console":
		link = profile.ConsoleURL
	case "detail":
		link = profile.DetailURL
	default:
		writeError(w, http.StatusBadRequest, errors.New("kind must be console or detail"))
		return
	}
	if strings.TrimSpace(link) == "" {
		writeError(w, http.StatusNotFound, errors.New("link is not set"))
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), NodeID: profile.NodeID, Action: "inventory.link.reveal", Scope: "inventory:admin", Metadata: map[string]string{"machine_id": profile.ID, "kind": req.Kind}})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": profile.ID, "kind": req.Kind, "url": link})
}

func (s *Server) machineViewsForPrincipal(p principal) []machineView {
	now := s.now()
	profiles := map[string]model.MachineProfile{}
	for _, profile := range s.store.MachineProfiles() {
		profiles[profile.NodeID] = profile
	}
	vendors := s.machineVendorMap()
	views := []machineView{}
	seen := map[string]bool{}
	for _, node := range s.store.Nodes() {
		if !rbac.Allows(p.Principal, "inventory:read", node.ID) {
			continue
		}
		seen[node.ID] = true
		views = append(views, toMachineView(node, profiles[node.ID], vendors, now))
	}
	for _, profile := range profiles {
		if seen[profile.NodeID] || !rbac.Allows(p.Principal, "inventory:read", profile.NodeID) {
			continue
		}
		views = append(views, toMachineView(model.Node{ID: profile.NodeID}, profile, vendors, now))
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].NodeName == views[j].NodeName {
			return views[i].NodeID < views[j].NodeID
		}
		return views[i].NodeName < views[j].NodeName
	})
	return views
}

func (s *Server) machineVendorMap() map[string]model.MachineVendor {
	out := map[string]model.MachineVendor{}
	for _, vendor := range s.store.MachineVendors() {
		key := strings.ToLower(strings.TrimSpace(vendor.Name))
		if key != "" {
			out[key] = vendor
		}
	}
	return out
}

func (s *Server) machineVendorsForPrincipal(p principal) []model.MachineVendor {
	seen := map[string]model.MachineVendor{}
	for _, vendor := range s.store.MachineVendors() {
		key := strings.ToLower(strings.TrimSpace(vendor.Name))
		if key == "" {
			continue
		}
		seen[key] = vendor
	}
	for _, profile := range s.store.MachineProfiles() {
		if !rbac.Allows(p.Principal, "inventory:read", profile.NodeID) {
			continue
		}
		name := strings.TrimSpace(profile.Vendor)
		key := strings.ToLower(name)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; !ok {
			seen[key] = model.MachineVendor{ID: "derived:" + key, Name: name}
		}
	}
	out := make([]model.MachineVendor, 0, len(seen))
	for _, vendor := range seen {
		out = append(out, vendor)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func toMachineView(node model.Node, profile model.MachineProfile, vendors map[string]model.MachineVendor, now time.Time) machineView {
	purchasedAt := optionalDate(profile.PurchasedAt)
	nextRenewal := optionalDate(profile.NextRenewal)
	var daysUntil *int
	if nextRenewal != nil {
		days := daysUntilRenewal(now, *nextRenewal)
		daysUntil = &days
	}
	var vendorProfile *model.MachineVendor
	if vendor, ok := vendors[strings.ToLower(strings.TrimSpace(profile.Vendor))]; ok {
		v := vendor
		vendorProfile = &v
	}
	return machineView{
		ID:               profile.ID,
		NodeID:           firstNonEmpty(profile.NodeID, node.ID),
		NodeName:         node.Name,
		Label:            profile.Label,
		Online:           node.Online,
		HostFacts:        node.HostFacts,
		Vendor:           profile.Vendor,
		VendorProfile:    vendorProfile,
		Region:           profile.Region,
		HasConsoleURL:    profile.ConsoleURL != "",
		HasDetailURL:     profile.DetailURL != "",
		Notes:            profile.Notes,
		PriceCents:       profile.PriceCents,
		Currency:         profile.Currency,
		PurchasedAt:      purchasedAt,
		RenewalCycle:     profile.RenewalCycle,
		CycleDays:        profile.CycleDays,
		NextRenewal:      nextRenewal,
		DaysUntilRenewal: daysUntil,
		AutoRoll:         profile.AutoRoll,
		RemindDaysBefore: append([]int(nil), profile.RemindDaysBefore...),
		RemindersEnabled: profile.RemindersEnabled,
		CreatedAt:        profile.CreatedAt,
		UpdatedAt:        profile.UpdatedAt,
	}
}

func optionalDate(input time.Time) *time.Time {
	date := dateOnlyUTC(input)
	if date.IsZero() {
		return nil
	}
	return &date
}

func (s *Server) machineProfileFromRequest(req machineProfileRequest, existing model.MachineProfile, create bool) (model.MachineProfile, error) {
	out := existing
	if create {
		out = model.MachineProfile{}
	} else if strings.TrimSpace(req.ID) == "" || strings.TrimSpace(req.ID) != existing.ID {
		return model.MachineProfile{}, errors.New("valid id is required")
	}
	out.ID = strings.TrimSpace(req.ID)
	if create || req.has("node_id") {
		out.NodeID = strings.TrimSpace(req.NodeID)
	}
	if out.NodeID == "" {
		return model.MachineProfile{}, errors.New("node_id is required")
	}
	if create || req.has("label") {
		out.Label = clampPrintable(req.Label, maxMachineShort)
	}
	if create || req.has("vendor") {
		out.Vendor = clampPrintable(req.Vendor, maxMachineShort)
	}
	if create || req.has("region") {
		out.Region = clampPrintable(req.Region, maxMachineShort)
	}
	if create || req.has("notes") {
		out.Notes = clampPrintable(req.Notes, maxMachineNotes)
	}
	if create || req.ConsoleURL != "" || req.ClearConsoleURL {
		out.ConsoleURL = clampPrintable(req.ConsoleURL, maxMachineURL)
	}
	if create || req.DetailURL != "" || req.ClearDetailURL {
		out.DetailURL = clampPrintable(req.DetailURL, maxMachineURL)
	}
	if create || req.has("price_cents") {
		out.PriceCents = req.PriceCents
	}
	if create || req.has("currency") {
		out.Currency = strings.ToUpper(clampPrintable(req.Currency, 12))
	}
	if create || req.has("purchased_at") {
		out.PurchasedAt = dateOnlyUTC(req.PurchasedAt)
	}
	if create || req.has("renewal_cycle") {
		out.RenewalCycle = clampPrintable(req.RenewalCycle, maxMachineShort)
	}
	if create || req.has("cycle_days") {
		out.CycleDays = req.CycleDays
	}
	if create || req.has("next_renewal") {
		out.NextRenewal = dateOnlyUTC(req.NextRenewal)
	}
	if create || req.has("auto_roll") {
		out.AutoRoll = req.AutoRoll
	}
	if create || req.has("remind_days_before") {
		out.RemindDaysBefore = normalizeReminderDays(req.RemindDaysBefore)
	}
	if create || req.has("reminders_enabled") {
		out.RemindersEnabled = req.RemindersEnabled
	}
	if create {
		out.LastRemindedKey = ""
	} else if req.has("last_reminded_key") && req.LastRemindedKey != "" {
		// LastRemindedKey is server-managed; clients cannot forge it.
		return model.MachineProfile{}, errors.New("last_reminded_key is server-managed")
	}
	if err := validateMachineProfile(out); err != nil {
		return model.MachineProfile{}, err
	}
	return out, nil
}

func (s *Server) machineVendorFromRequest(req machineVendorRequest) (model.MachineVendor, error) {
	name := clampPrintable(req.Name, maxMachineShort)
	if name == "" {
		return model.MachineVendor{}, errors.New("name is required")
	}
	vendor := model.MachineVendor{ID: strings.TrimSpace(req.ID)}
	if strings.HasPrefix(vendor.ID, "derived:") {
		vendor.ID = ""
	}
	if vendor.ID != "" {
		if existing, ok := s.store.MachineVendor(vendor.ID); ok {
			vendor = existing
		}
	} else if existing, ok := s.store.MachineVendorByName(name); ok {
		vendor = existing
	} else {
		vendor.ID = id.New("vendor")
	}
	vendor.Name = name
	vendor.URL = clampPrintable(req.URL, maxMachineURL)
	vendor.LogoURL = clampPrintable(req.LogoURL, maxMachineURL)
	vendor.Description = clampPrintable(req.Description, maxMachineNotes)
	if vendor.URL != "" && !validHTTPURL(vendor.URL) {
		return model.MachineVendor{}, errors.New("url must be an absolute http(s) URL")
	}
	if vendor.LogoURL != "" && !validHTTPURL(vendor.LogoURL) {
		return model.MachineVendor{}, errors.New("logo_url must be an absolute http(s) URL")
	}
	return vendor, nil
}

func validateMachineProfile(p model.MachineProfile) error {
	if p.NodeID == "" {
		return errors.New("node_id is required")
	}
	if p.PriceCents < 0 {
		return errors.New("price_cents cannot be negative")
	}
	if p.PriceCents > 0 && !validCurrency(p.Currency) {
		return errors.New("currency must be a 3-5 character code such as USD, CNY, USDT, or USDC when price_cents is set")
	}
	switch p.RenewalCycle {
	case "":
		if p.CycleDays != 0 {
			return errors.New("cycle_days requires custom_days renewal_cycle")
		}
	case model.RenewalCycleMonthly, model.RenewalCycleQuarterly, model.RenewalCycleSemiannual, model.RenewalCycleAnnual:
		if p.CycleDays != 0 {
			return errors.New("cycle_days is only valid for custom_days")
		}
	case model.RenewalCycleCustomDays:
		if p.CycleDays <= 0 || p.CycleDays > 3650 {
			return errors.New("custom_days cycle requires cycle_days between 1 and 3650")
		}
	default:
		return fmt.Errorf("unknown renewal_cycle %q", p.RenewalCycle)
	}
	if p.RemindersEnabled && p.NextRenewal.IsZero() {
		return errors.New("next_renewal is required when reminders are enabled")
	}
	if p.AutoRoll && p.RenewalCycle == "" {
		return errors.New("renewal_cycle is required when auto_roll is enabled")
	}
	return nil
}

func normalizeReminderDays(in []int) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, d := range in {
		if d < 0 || d > 3650 || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

func validCurrency(value string) bool {
	if len(value) < 3 || len(value) > 5 {
		return false
	}
	for _, r := range value {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func validHTTPURL(value string) bool {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if u.User != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func (s *Server) startRenewalScheduler() {
	interval := s.reminderInterval
	go func() {
		s.evaluateReminders(s.now())
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.evaluateReminders(s.now())
		}
	}()
}

const (
	// nodeOfflineThreshold is how long a node may go without a heartbeat before
	// the liveness sweep marks it offline. The agent beats ~every 10s by default,
	// so 90s tolerates several missed beats / a brief agent restart without
	// flapping, while still surfacing a genuinely dead node within ~2 minutes.
	nodeOfflineThreshold = 90 * time.Second
	// nodeLivenessSweepInterval is how often the liveness sweep runs.
	nodeLivenessSweepInterval = 20 * time.Second
)

// startNodeLivenessSweeper periodically flips nodes whose heartbeat has gone
// stale to offline. Without it, model.Node.Online (set true on every beat and
// never reset) stayed sticky-true after an agent died, so the fleet kept showing
// dead nodes as online and geo-routing kept treating them as healthy.
func (s *Server) startNodeLivenessSweeper() {
	go func() {
		s.sweepNodeLiveness(s.now())
		ticker := time.NewTicker(nodeLivenessSweepInterval)
		defer ticker.Stop()
		for range ticker.C {
			s.sweepNodeLiveness(s.now())
		}
	}()
}

func (s *Server) sweepNodeLiveness(now time.Time) {
	flipped, err := s.store.MarkStaleNodesOffline(nodeOfflineThreshold, now)
	if err != nil {
		s.logger.Printf("node liveness sweep: %v", err)
	}
	for _, n := range flipped {
		name := n.Name
		if name == "" {
			name = n.ID
		}
		s.recordAudit(model.AuditEvent{
			ID:     id.New("audit"),
			NodeID: n.ID,
			Action: "node.offline",
			Scope:  "node:read",
			Reason: "no heartbeat within liveness threshold",
		})
		s.emitNotify("🔌 节点离线", fmt.Sprintf("节点 %s (%s) 超过 %s 未上报心跳，已标记为离线。", name, n.ID, nodeOfflineThreshold))
	}
}

func (s *Server) evaluateReminders(now time.Time) {
	fired, err := s.evaluateMachineReminders(now, "", nil)
	if err != nil {
		s.logger.Printf("inventory reminders: %v", err)
	} else {
		for _, fire := range fired {
			s.recordAudit(model.AuditEvent{
				ID:     id.New("audit"),
				NodeID: fire.NodeID,
				Action: "inventory.reminder",
				Scope:  "inventory:admin",
				Metadata: map[string]string{
					"machine_id":   fire.MachineID,
					"offset_days":  strconv.Itoa(fire.OffsetDays),
					"next_renewal": fire.NextRenewal,
				},
			})
		}
	}
	if _, err := s.evaluateProxyUserNotifications(now, ""); err != nil {
		s.logger.Printf("proxy user notifications: %v", err)
	}
	s.evaluateProxyConfigDrift(now)
	s.evaluateAgentUpdatePolicies(now)
}

func (s *Server) evaluateMachineReminders(now time.Time, onlyID string, allow func(model.MachineProfile) bool) ([]renewalReminderFire, error) {
	profiles := s.store.MachineProfiles()
	fired := []renewalReminderFire{}
	found := onlyID == ""
	for _, profile := range profiles {
		if onlyID != "" && profile.ID != onlyID {
			continue
		}
		found = true
		if allow != nil && !allow(profile) {
			continue
		}
		fire, ok := nextReminderFire(profile, now)
		if !ok {
			continue
		}
		profile.LastRemindedKey = reminderKey(profile.NextRenewal, fire.OffsetDays)
		if err := s.store.UpsertMachineProfile(profile); err != nil {
			return nil, err
		}
		node, _ := s.store.Node(profile.NodeID)
		fire.MachineID = profile.ID
		fire.NodeID = profile.NodeID
		fire.NodeName = firstNonEmpty(node.Name, profile.Label, profile.NodeID)
		fire.NextRenewal = dateOnlyUTC(profile.NextRenewal).Format("2006-01-02")
		fired = append(fired, fire)
		s.emitRenewalReminder(profile, node, fire)
	}
	if !found {
		return nil, errors.New("machine profile not found")
	}
	return fired, nil
}

func nextReminderFire(profile model.MachineProfile, now time.Time) (renewalReminderFire, bool) {
	if !profile.RemindersEnabled || profile.NextRenewal.IsZero() {
		return renewalReminderFire{}, false
	}
	days := daysUntilRenewal(now, profile.NextRenewal)
	offsets := append([]int(nil), profile.RemindDaysBefore...)
	sort.Ints(offsets)
	if days >= 0 {
		for _, offset := range offsets {
			if days <= offset && reminderOffsetCanFire(profile.LastRemindedKey, profile.NextRenewal, offset) {
				return renewalReminderFire{OffsetDays: offset}, true
			}
		}
	} else {
		for _, offset := range offsets {
			if reminderOffsetCanFire(profile.LastRemindedKey, profile.NextRenewal, offset) {
				// Catch up with the closest missed positive reminder before the
				// overdue sentinel. This avoids skipping the final warning when a
				// server was down at the exact threshold.
				return renewalReminderFire{OffsetDays: offset}, true
			}
		}
		if reminderOffsetCanFire(profile.LastRemindedKey, profile.NextRenewal, -1) {
			return renewalReminderFire{OffsetDays: -1}, true
		}
	}
	return renewalReminderFire{}, false
}

func (s *Server) emitRenewalReminder(profile model.MachineProfile, node model.Node, fire renewalReminderFire) {
	name := firstNonEmpty(profile.Label, node.Name, profile.NodeID)
	when := dateOnlyUTC(profile.NextRenewal).Format("2006-01-02")
	price := ""
	if profile.PriceCents > 0 && profile.Currency != "" {
		price = fmt.Sprintf(" — %s %.2f", profile.Currency, float64(profile.PriceCents)/100.0)
	}
	due := "overdue"
	if fire.OffsetDays >= 0 {
		due = fmt.Sprintf("due in %dd", fire.OffsetDays)
	}
	title := fmt.Sprintf("Lattice renewal %s: %s", due, name)
	body := fmt.Sprintf("%s (%s, %s) renews %s%s. Mark renewed in the dashboard.",
		name, firstNonEmpty(profile.Vendor, "unknown vendor"), firstNonEmpty(profile.Region, "unknown region"), when, price)
	s.emitNotify(title, body)
}

func reminderOffsetCanFire(lastKey string, renewal time.Time, offset int) bool {
	date := dateOnlyUTC(renewal).Format("2006-01-02")
	if lastKey == "" {
		return true
	}
	parts := strings.Split(lastKey, ":")
	if len(parts) != 2 || parts[0] != date {
		return true
	}
	last, err := strconv.Atoi(parts[1])
	if err != nil {
		return true
	}
	return offset < last
}

func reminderKey(renewal time.Time, offset int) string {
	return dateOnlyUTC(renewal).Format("2006-01-02") + ":" + strconv.Itoa(offset)
}

func daysUntilRenewal(now, renewal time.Time) int {
	if renewal.IsZero() {
		return 0
	}
	return int(dateOnlyUTC(renewal).Sub(dateOnlyUTC(now)).Hours() / 24)
}

func advanceRenewal(from time.Time, cycle string, cycleDays int) (time.Time, error) {
	if from.IsZero() {
		return time.Time{}, errors.New("next_renewal is required for auto_roll")
	}
	base := dateOnlyUTC(from)
	switch cycle {
	case model.RenewalCycleMonthly:
		return base.AddDate(0, 1, 0), nil
	case model.RenewalCycleQuarterly:
		return base.AddDate(0, 3, 0), nil
	case model.RenewalCycleSemiannual:
		return base.AddDate(0, 6, 0), nil
	case model.RenewalCycleAnnual:
		return base.AddDate(1, 0, 0), nil
	case model.RenewalCycleCustomDays:
		if cycleDays <= 0 {
			return time.Time{}, errors.New("cycle_days is required for custom_days")
		}
		return base.AddDate(0, 0, cycleDays), nil
	default:
		return time.Time{}, fmt.Errorf("unknown renewal_cycle %q", cycle)
	}
}

func dateOnlyUTC(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
