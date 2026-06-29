package plugin

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/LatticeNet/lattice-server/internal/rbac"
)

// Design-10: a plugin contributes dashboard UI and declares the interfaces it
// exposes — as DATA, never code. The dashboard renders a FIXED set of view
// primitives parameterized by these declarations, so strict CSP holds and the
// only trust surface is the (signed) manifest + the (capability-gated) gateway.

// Allow-lists. Anything outside these is rejected at validation, so a manifest
// can never smuggle an unknown renderer, primitive, or target section.
var (
	pluginNavSections = map[string]bool{"plugins": true, "proxy": true}
	pluginViewKinds   = map[string]bool{"table": true, "detail": true, "form": true, "kv": true, "markdown": true, "builtin": true}
	pluginRenderHints = map[string]bool{"": true, "copy-secret": true, "bytes": true, "relative-time": true, "badge": true, "code": true}
	pluginFormKinds   = map[string]bool{"text": true, "int": true, "select": true}
	// Icons the dashboard knows (lucide names). Conservative starter set.
	pluginIcons = map[string]bool{
		"": true, "Radar": true, "Boxes": true, "Store": true, "ServerCog": true,
		"DoorOpen": true, "Users": true, "Link": true, "Gauge": true, "Blocks": true,
	}
	pluginSectionRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,48}$`)
	pluginRouteRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9/_-]{0,64}$`)
	pluginKeyRe           = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,48}$`)
	pluginMethodRe        = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,48}$`)
	pluginServiceSuffixRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
	pluginBuiltinViews    = map[string]string{
		"vpn-core.lines":         "latticenet.vpn-core",
		"vpn-core.users":         "latticenet.vpn-core",
		"vpn-core.usage":         "latticenet.vpn-core",
		"vpn-core.profiles":      "latticenet.vpn-core",
		"vpn-core.subscriptions": "latticenet.vpn-core",
		"proxy.inbounds":         "latticenet.vpn-core",
		"proxy.users":            "latticenet.vpn-core",
		"proxy.profiles":         "latticenet.vpn-core",
		"proxy.subscriptions":    "latticenet.vpn-core",
		"proxy.usage":            "latticenet.vpn-core",
		"proxy.discovered":       "latticenet.vpn-core",
		"proxy.substore":         "latticenet.sub-store",
	}
)

// NavContribution is a sidebar entry a plugin adds. Route is plugin-relative and
// mounted at /plugins/<id>/<route>.
type NavContribution struct {
	Section      string   `json:"section"`
	SectionTitle string   `json:"section_title,omitempty"`
	Title        string   `json:"title"`
	Route        string   `json:"route"`
	Icon         string   `json:"icon,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// ViewSource binds a view's data to a plugin interface method.
type ViewSource struct {
	Interface string `json:"interface"`
	Method    string `json:"method"`
}

// ViewColumn is one table column. Render selects a safe dashboard formatter.
type ViewColumn struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Render string `json:"render,omitempty"`
}

// ViewFormField is one input in an action form.
type ViewFormField struct {
	Key     string   `json:"key"`
	Label   string   `json:"label,omitempty"`
	Kind    string   `json:"kind"`
	Options []string `json:"options,omitempty"`
}

// ViewAction is a button that calls an interface method (optionally with a form).
type ViewAction struct {
	Label     string          `json:"label"`
	Interface string          `json:"interface"`
	Method    string          `json:"method"`
	Form      []ViewFormField `json:"form,omitempty"`
	Scopes    []string        `json:"scopes,omitempty"`
}

// ViewContribution is one declarative view rendered by a fixed dashboard primitive.
type ViewContribution struct {
	Route        string       `json:"route"`
	Title        string       `json:"title"`
	Kind         string       `json:"kind"`
	ComponentKey string       `json:"component_key,omitempty"`
	Source       *ViewSource  `json:"source,omitempty"`
	Columns      []ViewColumn `json:"columns,omitempty"`
	Actions      []ViewAction `json:"actions,omitempty"`
}

// ManifestUI is a plugin's dashboard contribution set.
type ManifestUI struct {
	Nav   []NavContribution  `json:"nav,omitempty"`
	Views []ViewContribution `json:"views,omitempty"`
}

// InterfaceContract declares an interface the plugin exposes (service + methods),
// callable through the dashboard->plugin gateway under the given scopes.
type InterfaceContract struct {
	Service string   `json:"service"`
	Methods []string `json:"methods"`
	Scopes  []string `json:"scopes,omitempty"`
}

// validateContributions checks a manifest's ui + interfaces against the
// allow-lists. Empty contributions are valid (most plugins have none).
func validateContributions(m Manifest) error {
	contracts := map[string]map[string][]string{}
	for _, c := range m.Interfaces {
		if c.Service == "" {
			return fmt.Errorf("interface service is required")
		}
		if !serviceOwnedByPlugin(m.ID, c.Service) {
			return fmt.Errorf("interface service %q must be under plugin id %q", c.Service, m.ID)
		}
		if len(c.Methods) == 0 {
			return fmt.Errorf("interface %q must declare at least one method", c.Service)
		}
		for _, s := range c.Scopes {
			if !scopeAllowedInManifest(s) {
				return fmt.Errorf("interface %q invalid scope %q", c.Service, s)
			}
		}
		if contracts[c.Service] == nil {
			contracts[c.Service] = map[string][]string{}
		}
		seenMethods := map[string]bool{}
		for _, method := range c.Methods {
			if !pluginMethodRe.MatchString(method) {
				return fmt.Errorf("interface %q invalid method %q", c.Service, method)
			}
			if seenMethods[method] {
				return fmt.Errorf("interface %q duplicate method %q", c.Service, method)
			}
			seenMethods[method] = true
			contracts[c.Service][method] = c.Scopes
		}
	}
	if m.UI == nil {
		return nil
	}
	for _, n := range m.UI.Nav {
		if !sectionAllowed(n.Section) {
			return fmt.Errorf("nav section %q is not allowed", n.Section)
		}
		if n.Title == "" || !pluginRouteRe.MatchString(n.Route) {
			return fmt.Errorf("nav entry needs a title and a valid route (got route %q)", n.Route)
		}
		if !pluginIcons[n.Icon] {
			return fmt.Errorf("nav icon %q is not allowed", n.Icon)
		}
		for _, s := range n.Scopes {
			if !scopeAllowedInManifest(s) {
				return fmt.Errorf("nav scope %q invalid", s)
			}
		}
	}
	for _, v := range m.UI.Views {
		if !pluginRouteRe.MatchString(v.Route) || v.Title == "" {
			return fmt.Errorf("view needs a title and a valid route (got %q)", v.Route)
		}
		if !pluginViewKinds[v.Kind] {
			return fmt.Errorf("view kind %q is not allowed", v.Kind)
		}
		if v.Kind == "builtin" {
			owner, ok := pluginBuiltinViews[v.ComponentKey]
			if !ok || owner != m.ID {
				return fmt.Errorf("view %q builtin component %q is not allowed for plugin %q", v.Route, v.ComponentKey, m.ID)
			}
		} else if v.ComponentKey != "" {
			return fmt.Errorf("view %q component_key requires builtin kind", v.Route)
		}
		if v.Source != nil {
			if !methodDeclared(contracts, v.Source.Interface, v.Source.Method) {
				return fmt.Errorf("view %q source %s/%s is not declared in interfaces", v.Route, v.Source.Interface, v.Source.Method)
			}
		}
		for _, col := range v.Columns {
			if !pluginKeyRe.MatchString(col.Key) || !pluginRenderHints[col.Render] {
				return fmt.Errorf("view %q invalid column (key %q render %q)", v.Route, col.Key, col.Render)
			}
		}
		for _, a := range v.Actions {
			if a.Label == "" || a.Interface == "" || a.Method == "" {
				return fmt.Errorf("view %q action needs label/interface/method", v.Route)
			}
			contractScopes, declared := declaredMethodScopes(contracts, a.Interface, a.Method)
			if !declared {
				return fmt.Errorf("view %q action %s/%s is not declared in interfaces", v.Route, a.Interface, a.Method)
			}
			if len(contractScopes) == 0 && len(a.Scopes) == 0 {
				return fmt.Errorf("view %q action %s/%s must declare scopes or inherit scoped interface", v.Route, a.Interface, a.Method)
			}
			for _, s := range a.Scopes {
				if !scopeAllowedInManifest(s) {
					return fmt.Errorf("view %q action scope %q invalid", v.Route, s)
				}
			}
			for _, f := range a.Form {
				if !pluginKeyRe.MatchString(f.Key) || !pluginFormKinds[f.Kind] {
					return fmt.Errorf("view %q action form invalid field (key %q kind %q)", v.Route, f.Key, f.Kind)
				}
			}
		}
	}
	return nil
}

func sectionAllowed(section string) bool {
	return pluginNavSections[section] || pluginSectionRe.MatchString(section)
}

func serviceOwnedByPlugin(pluginID, service string) bool {
	suffix := strings.TrimPrefix(service, pluginID+"/")
	return suffix != service && pluginServiceSuffixRe.MatchString(suffix)
}

func methodDeclared(contracts map[string]map[string][]string, service, method string) bool {
	_, ok := declaredMethodScopes(contracts, service, method)
	return ok
}

func declaredMethodScopes(contracts map[string]map[string][]string, service, method string) ([]string, bool) {
	if contracts[service] == nil {
		return nil, false
	}
	scopes, ok := contracts[service][method]
	return scopes, ok
}

// scopeLooksValid bounds an RBAC scope token shape (domain:action). The dashboard
// + server RBAC enforce the actual scope; this only rejects malformed values.
func scopeLooksValid(s string) bool {
	return regexp.MustCompile(`^[a-z][a-z0-9]*:[a-z][a-z0-9]*$`).MatchString(s)
}

func scopeAllowedInManifest(s string) bool {
	return scopeLooksValid(s) && rbac.ValidScope(s)
}
