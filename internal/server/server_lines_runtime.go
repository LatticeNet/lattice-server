package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
	"github.com/LatticeNet/lattice-server/internal/id"
)

func (s *Server) findLine(nodeID, lineHashID string) (Line, bool) {
	for _, g := range s.buildLineGroups() {
		if nodeID != "" && g.NodeID != nodeID {
			continue
		}
		for _, ln := range g.Lines {
			if ln.LineHashID == lineHashID {
				return ln, true
			}
		}
	}
	return Line{}, false
}

func uniqueNonEmpty(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

type singBoxUserPayload struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	Username string `json:"username,omitempty"`
	Flow     string `json:"flow,omitempty"`
	Method   string `json:"method,omitempty"`
	Security string `json:"security,omitempty"`
}

func singBoxUserPayloadForLine(u VpnUser, line Line, flowOverride string) (string, error) {
	proto := normalizeSingBoxCredentialProtocol(line.Type)
	if proto == "" {
		return "", fmt.Errorf("unsupported line protocol %q", line.Type)
	}
	cred, ok := vpnCredentialForProtocol(u.Credentials, proto)
	if !ok {
		return "", fmt.Errorf("no %s credential", proto)
	}
	payload := singBoxUserPayload{
		UserID:   u.ID,
		Email:    strings.TrimSpace(u.Email),
		Name:     strings.TrimSpace(u.Name),
		Protocol: proto,
		Flow:     firstNonEmpty(strings.TrimSpace(flowOverride), strings.TrimSpace(cred.Flow)),
		Method:   strings.TrimSpace(cred.Method),
		Security: strings.TrimSpace(cred.Security),
	}
	switch proto {
	case "vless", "vmess", "tuic":
		payload.UUID = strings.TrimSpace(cred.UUID)
		if payload.UUID == "" {
			return "", errors.New("uuid credential is empty")
		}
	case "trojan", "hysteria2", "anytls":
		payload.Password = cred.Password
		if payload.Password == "" {
			return "", errors.New("password credential is empty")
		}
	case "socks":
		payload.Username = firstNonEmpty(strings.TrimSpace(u.Email), strings.TrimSpace(u.Name), u.ID)
		payload.Password = cred.Password
		if payload.Password == "" {
			return "", errors.New("password credential is empty")
		}
	default:
		return "", fmt.Errorf("unsupported line protocol %q", line.Type)
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func normalizeSingBoxCredentialProtocol(proto string) string {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "vless", "reality":
		return "vless"
	case "vmess":
		return "vmess"
	case "tuic":
		return "tuic"
	case "trojan":
		return "trojan"
	case "hysteria2", "hy2":
		return "hysteria2"
	case "anytls":
		return "anytls"
	case "socks":
		return "socks"
	case "shadowsocks", "ss":
		return "shadowsocks"
	default:
		return ""
	}
}

func vpnCredentialForProtocol(creds []VpnCredential, proto string) (VpnCredential, bool) {
	for _, c := range creds {
		if normalizeSingBoxCredentialProtocol(c.Protocol) == proto {
			return c, true
		}
	}
	return VpnCredential{}, false
}

func (s *Server) updateVpnUserLineBindings(lineHash string, bindIDs, unbindIDs []string) error {
	bindSet := map[string]bool{}
	for _, id := range bindIDs {
		bindSet[id] = true
	}
	unbindSet := map[string]bool{}
	for _, id := range unbindIDs {
		unbindSet[id] = true
	}
	now := s.now()
	for userID := range bindSet {
		u, ok := s.getVpnUser(userID)
		if !ok {
			return fmt.Errorf("vpn user %q not found", userID)
		}
		found := false
		for i := range u.Bindings {
			if u.Bindings[i].LineHashID == lineHash {
				u.Bindings[i].Enabled = true
				found = true
				break
			}
		}
		if !found {
			u.Bindings = append(u.Bindings, LineBinding{LineHashID: lineHash, Enabled: true})
		}
		u.UpdatedAt = now
		if err := s.putVpnUser(u); err != nil {
			return err
		}
	}
	for userID := range unbindSet {
		u, ok := s.getVpnUser(userID)
		if !ok {
			return fmt.Errorf("vpn user %q not found", userID)
		}
		kept := u.Bindings[:0]
		for _, b := range u.Bindings {
			if b.LineHashID != lineHash {
				kept = append(kept, b)
			}
		}
		u.Bindings = kept
		u.UpdatedAt = now
		if err := s.putVpnUser(u); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleRevealVPNUserCredentials(w http.ResponseWriter, r *http.Request, p principal) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var req struct {
		ID          string `json:"id"`
		StepUpGrant string `json:"step_up_grant"`
	}
	if !decodeClientJSON(w, r, &req) {
		return
	}
	if !s.requireScope(w, p, "proxy:admin") {
		return
	}
	if !s.requireStepUpGrant(w, p, strings.TrimSpace(req.StepUpGrant), "vpn.user.credentials.reveal") {
		return
	}
	u, ok := s.getVpnUser(strings.TrimSpace(req.ID))
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("vpn user not found"))
		return
	}
	s.recordPrincipalAudit(p, model.AuditEvent{ID: id.New("audit"), Action: "vpn.user.credentials.reveal", Scope: "proxy:admin", Metadata: map[string]string{"user_id": u.ID}})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"user":        toVpnUserView(u),
		"credentials": u.Credentials,
		"sub_id":      u.SubID,
	})
}
