package plugin

import (
	"bytes"
	"encoding/json"
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
	pluginViewKinds   = map[string]bool{"table": true, "detail": true, "form": true, "kv": true, "markdown": true, "sandbox": true}
	pluginRenderHints = map[string]bool{"": true, "copy-secret": true, "bytes": true, "relative-time": true, "badge": true, "code": true}
	pluginFormKinds   = map[string]bool{"text": true, "int": true, "select": true}
	// Icons the dashboard knows (lucide names). Conservative starter set.
	pluginIcons = map[string]bool{
		"": true, "Radar": true, "Boxes": true, "Store": true, "ServerCog": true,
		"DoorOpen": true, "Users": true, "Link": true, "Gauge": true, "Blocks": true,
		"Shield": true, "Spline": true,
	}
	pluginSectionRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,48}$`)
	pluginRouteRe         = regexp.MustCompile(`^[a-z0-9][a-z0-9/_-]{0,64}$`)
	pluginKeyRe           = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,48}$`)
	pluginMethodRe        = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,48}$`)
	pluginServiceSuffixRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)
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
	Route   string       `json:"route"`
	Title   string       `json:"title"`
	Kind    string       `json:"kind"`
	Source  *ViewSource  `json:"source,omitempty"`
	Columns []ViewColumn `json:"columns,omitempty"`
	Actions []ViewAction `json:"actions,omitempty"`
}

// ManifestUI is a plugin's dashboard contribution set.
type ManifestUI struct {
	Nav   []NavContribution  `json:"nav,omitempty"`
	Views []ViewContribution `json:"views,omitempty"`
}

// Backing names who actually serves an interface's methods.
//
// A plugin is not required to carry its own engine. Some domain engines — the
// nftables renderer, the WireGuard key/config engine — deliberately stay in core so
// the trust base stays small (ADR-001 D5). What the plugin owns in that case is the
// UI, the validation, and the workflow intent; core owns the engine.
//
// That arrangement is legitimate. What is not legitimate is leaving it implicit: a
// manifest that declares a method core secretly answers is a contract that lies, and
// no operator or auditor can see the difference. Backing makes the split an explicit,
// signed, per-service declaration.
const (
	// BackingRuntime: the plugin's own artifact serves the method. The default.
	BackingRuntime = "runtime"
	// BackingCore: a core-registered provider owned by this plugin serves the method.
	// Host-risk by nature — only a system plugin may declare it, and every v2 manifest
	// already requires a trusted-publisher signature.
	BackingCore = "core"
)

// InterfaceContract declares an interface the plugin exposes (service + methods),
// callable through the dashboard->plugin gateway under the given scopes.
type InterfaceContract struct {
	Service string `json:"service"`
	// Methods remains the normalized name list so v1 callers keep their source
	// contract. MethodSpecs carries the signed v2 effect and method-level scopes.
	Methods     []string          `json:"-"`
	MethodSpecs []InterfaceMethod `json:"-"`
	Scopes      []string          `json:"scopes,omitempty"`
	// Backing is empty on manifests signed before the field existed. Empty stays
	// omitted from the signing payload, so those signatures remain byte-identical
	// and valid; the gateway resolves them through a logged legacy path until they
	// are re-signed with an explicit declaration.
	Backing      string `json:"backing,omitempty"`
	typedMethods bool
}

// InterfaceFor returns the contract the manifest declares for a service.
func (m Manifest) InterfaceFor(service string) (InterfaceContract, bool) {
	for _, contract := range m.Interfaces {
		if contract.Service == service {
			return contract, true
		}
	}
	return InterfaceContract{}, false
}

// EffectiveBacking resolves the declared backing, defaulting to runtime.
func (c InterfaceContract) EffectiveBacking() string {
	if c.Backing == "" {
		return BackingRuntime
	}
	return c.Backing
}

// DeclaresBacking reports whether the manifest said who serves this service, rather
// than leaving the host to infer it.
func (c InterfaceContract) DeclaresBacking() bool {
	return c.Backing != ""
}

func (c InterfaceContract) MarshalJSON() ([]byte, error) {
	type stringMethods struct {
		Service string   `json:"service"`
		Methods []string `json:"methods"`
		Scopes  []string `json:"scopes,omitempty"`
		Backing string   `json:"backing,omitempty"`
	}
	type typedMethods struct {
		Service string            `json:"service"`
		Methods []InterfaceMethod `json:"methods"`
		Scopes  []string          `json:"scopes,omitempty"`
		Backing string            `json:"backing,omitempty"`
	}
	if c.typedMethods || len(c.MethodSpecs) > 0 {
		return json.Marshal(typedMethods{Service: c.Service, Methods: c.MethodSpecs, Scopes: c.Scopes, Backing: c.Backing})
	}
	return json.Marshal(stringMethods{Service: c.Service, Methods: c.Methods, Scopes: c.Scopes, Backing: c.Backing})
}

func (c *InterfaceContract) UnmarshalJSON(data []byte) error {
	var raw struct {
		Service string          `json:"service"`
		Methods json.RawMessage `json:"methods"`
		Scopes  []string        `json:"scopes,omitempty"`
		Backing string          `json:"backing,omitempty"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	if err := ensureNoTrailingJSON(dec); err != nil {
		return err
	}
	*c = InterfaceContract{Service: raw.Service, Scopes: raw.Scopes, Backing: raw.Backing}
	if len(raw.Methods) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw.Methods, &c.Methods); err == nil {
		return nil
	}
	methodDec := json.NewDecoder(bytes.NewReader(raw.Methods))
	methodDec.DisallowUnknownFields()
	if err := methodDec.Decode(&c.MethodSpecs); err != nil {
		return fmt.Errorf("interface methods must be all strings or all typed objects: %w", err)
	}
	if err := ensureNoTrailingJSON(methodDec); err != nil {
		return fmt.Errorf("interface methods: %w", err)
	}
	c.typedMethods = true
	c.Methods = make([]string, len(c.MethodSpecs))
	for i, method := range c.MethodSpecs {
		c.Methods[i] = method.Name
	}
	return nil
}

func (c InterfaceContract) effectiveMethods() []InterfaceMethod {
	if c.typedMethods || len(c.MethodSpecs) > 0 {
		return c.MethodSpecs
	}
	out := make([]InterfaceMethod, len(c.Methods))
	for i, name := range c.Methods {
		out[i] = InterfaceMethod{Name: name, Effect: InterfaceEffectRead, Scopes: c.Scopes}
	}
	return out
}

func (c InterfaceContract) TypedMethods() bool {
	return c.typedMethods || len(c.MethodSpecs) > 0
}

func (c InterfaceContract) MethodContracts() []InterfaceMethod {
	methods := c.effectiveMethods()
	out := make([]InterfaceMethod, len(methods))
	for i, method := range methods {
		out[i] = method
		out[i].Scopes = append([]string(nil), method.Scopes...)
	}
	return out
}

func (c InterfaceContract) MethodContract(name string) (InterfaceMethod, bool) {
	for _, method := range c.effectiveMethods() {
		if method.Name == name {
			method.Scopes = append([]string(nil), method.Scopes...)
			return method, true
		}
	}
	return InterfaceMethod{}, false
}

func (c InterfaceContract) EffectiveMethodScopes(name string) ([]string, bool) {
	method, ok := c.MethodContract(name)
	if !ok {
		return nil, false
	}
	if len(method.Scopes) > 0 {
		return method.Scopes, true
	}
	return append([]string(nil), c.Scopes...), true
}

// validateContributions checks a manifest's ui + interfaces against the
// allow-lists. Empty contributions are valid (most plugins have none).
func validateContributions(m Manifest) error {
	contracts := map[string]map[string][]string{}
	hasOperatorTargetCapability := false
	for _, capability := range m.Capabilities {
		if capability == capHTTPOperatorTarget {
			hasOperatorTargetCapability = true
			break
		}
	}
	usesOperatorTargetBinding := false
	for _, c := range m.Interfaces {
		if c.Service == "" {
			return fmt.Errorf("interface service is required")
		}
		if !serviceOwnedByPlugin(m.ID, c.Service) {
			return fmt.Errorf("interface service %q must be under plugin id %q", c.Service, m.ID)
		}
		if m.Schema == ManifestSchemaV2 && contracts[c.Service] != nil {
			return fmt.Errorf("interface service %q is duplicated", c.Service)
		}
		methods := c.effectiveMethods()
		if len(methods) == 0 {
			return fmt.Errorf("interface %q must declare at least one method", c.Service)
		}
		if m.Schema == ManifestSchemaV2 && !c.typedMethods && len(c.MethodSpecs) == 0 {
			return fmt.Errorf("interface %q manifest v2 requires typed method objects", c.Service)
		}
		if m.Schema == "" && (c.typedMethods || len(c.MethodSpecs) > 0) {
			return fmt.Errorf("interface %q typed method objects require manifest schema v2", c.Service)
		}
		switch c.Backing {
		case "", BackingRuntime, BackingCore:
		default:
			return fmt.Errorf("interface %q has invalid backing %q (want %q or %q)",
				c.Service, c.Backing, BackingRuntime, BackingCore)
		}
		if c.Backing != "" && m.Schema != ManifestSchemaV2 {
			return fmt.Errorf("interface %q backing requires manifest schema v2", c.Service)
		}
		// Declaring that core serves a method is a claim on the host's own trust base,
		// so it is confined to system plugins. Every v2 manifest already requires a
		// trusted-publisher signature, so the declaration is signed by construction.
		if c.Backing == BackingCore && m.Type != TypeSystem {
			return fmt.Errorf("interface %q backing %q requires a system plugin", c.Service, BackingCore)
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
		for _, method := range methods {
			if !pluginMethodRe.MatchString(method.Name) {
				return fmt.Errorf("interface %q invalid method %q", c.Service, method.Name)
			}
			if seenMethods[method.Name] {
				return fmt.Errorf("interface %q duplicate method %q", c.Service, method.Name)
			}
			seenMethods[method.Name] = true
			effectiveScopes := c.Scopes
			if m.Schema == ManifestSchemaV2 {
				if method.Effect != InterfaceEffectRead && method.Effect != InterfaceEffectWrite && method.Effect != InterfaceEffectPlan {
					return fmt.Errorf("interface %q method %q has invalid effect %q", c.Service, method.Name, method.Effect)
				}
				for _, scope := range method.Scopes {
					if !scopeAllowedInManifest(scope) {
						return fmt.Errorf("interface %q method %q invalid scope %q", c.Service, method.Name, scope)
					}
				}
				if (method.Effect == InterfaceEffectWrite || method.Effect == InterfaceEffectPlan) && len(method.Scopes) == 0 {
					return fmt.Errorf("interface %q method %q effect %q requires method scopes", c.Service, method.Name, method.Effect)
				}
				if len(method.Scopes) > 0 {
					effectiveScopes = method.Scopes
				}
				if len(effectiveScopes) == 0 {
					return fmt.Errorf("interface %q method %q must declare scopes or inherit scoped interface", c.Service, method.Name)
				}
				if len(method.OperatorTargetFields) > 4 {
					return fmt.Errorf("interface %q method %q declares too many operator target fields", c.Service, method.Name)
				}
				seenTargetFields := map[string]bool{}
				for _, field := range method.OperatorTargetFields {
					if !pluginKeyRe.MatchString(field) {
						return fmt.Errorf("interface %q method %q has invalid operator target field %q", c.Service, method.Name, field)
					}
					if seenTargetFields[field] {
						return fmt.Errorf("interface %q method %q has duplicate operator target field %q", c.Service, method.Name, field)
					}
					seenTargetFields[field] = true
					usesOperatorTargetBinding = true
				}
				if len(method.OperatorTargetFields) > 0 && !hasOperatorTargetCapability {
					return fmt.Errorf("interface %q method %q operator target fields require %s capability", c.Service, method.Name, capHTTPOperatorTarget)
				}
			}
			contracts[c.Service][method.Name] = effectiveScopes
		}
	}
	if m.Schema == ManifestSchemaV2 && hasOperatorTargetCapability && !usesOperatorTargetBinding {
		return fmt.Errorf("manifest v2 capability %s requires a method-bound operator target field", capHTTPOperatorTarget)
	}
	if m.UI == nil {
		return nil
	}
	for _, n := range m.UI.Nav {
		if !sectionAllowed(m, n.Section) {
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
		if v.Kind == "sandbox" && m.UIRuntime == nil {
			return fmt.Errorf("view %q sandbox kind requires ui_runtime", v.Route)
		}
		if m.Schema == "" && v.Kind == "sandbox" {
			return fmt.Errorf("view %q sandbox kind requires manifest schema v2", v.Route)
		}
		if v.Kind == "sandbox" && (v.Source != nil || len(v.Columns) > 0 || len(v.Actions) > 0) {
			return fmt.Errorf("view %q sandbox kind cannot declare dashboard-rendered source, columns, or actions", v.Route)
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

func sectionAllowed(m Manifest, section string) bool {
	if m.Schema == ManifestSchemaV2 {
		return section == "extensions"
	}
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
