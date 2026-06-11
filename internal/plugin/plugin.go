package plugin

import (
	"errors"
	"fmt"
	"sort"
)

type Manifest struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Capabilities []string `json:"capabilities"`
}

var allowedCapabilities = map[string]bool{
	"kv:read":       true,
	"kv:write":      true,
	"static:read":   true,
	"static:write":  true,
	"worker:route":  true,
	"network:plan":  true,
	"network:apply": true,
	"task:run":      true,
	"notify:send":   true,
}

func ValidateManifest(m Manifest) error {
	if m.ID == "" || m.Name == "" {
		return errors.New("plugin id and name are required")
	}
	if m.Type != "system" && m.Type != "wasm" && m.Type != "worker" {
		return fmt.Errorf("unsupported plugin type %q", m.Type)
	}
	for _, cap := range m.Capabilities {
		if !allowedCapabilities[cap] {
			return fmt.Errorf("capability %q is not recognized", cap)
		}
	}
	return nil
}

func CapabilityList() []string {
	out := make([]string, 0, len(allowedCapabilities))
	for cap := range allowedCapabilities {
		out = append(out, cap)
	}
	sort.Strings(out)
	return out
}
