package plugin

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

const (
	ManifestSchemaV2           = "lattice.plugin.manifest.v2"
	BundleFormatTarGzip        = "tar+gzip"
	RuntimeProtocolStdioJSONV1 = "stdio-json-v1"
	UIRuntimeModeSandbox       = "sandbox"
	UIBridgeVersion1           = "1"

	InterfaceEffectRead  = "read"
	InterfaceEffectWrite = "write"
	InterfaceEffectPlan  = "plan"
)

var runtimePlatformRe = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9][a-z0-9_]*$`)
var pluginVersionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$`)

type BundleSpec struct {
	Format       string `json:"format"`
	DigestSHA256 string `json:"digest_sha256"`
}

type RuntimeSpec struct {
	Protocol    string            `json:"protocol"`
	Entrypoints map[string]string `json:"entrypoints"`
}

type UIRuntimeSpec struct {
	Mode          string `json:"mode"`
	Entrypoint    string `json:"entrypoint"`
	BridgeVersion string `json:"bridge_version"`
}

type CompatibilitySpec struct {
	Server          string `json:"server"`
	DashboardHost   string `json:"dashboard_host"`
	RuntimeProtocol string `json:"runtime_protocol"`
}

// HostAccessSpec declares host-mediated dependencies owned by another plugin.
// It is signed manifest data; the server grants it only while this plugin is
// active and revokes it on disable. UI code never receives this structure.
type HostAccessSpec struct {
	RPC []RPCDependency `json:"rpc,omitempty"`
}

type RPCDependency struct {
	Service string   `json:"service"`
	Methods []string `json:"methods"`
}

type InterfaceMethod struct {
	Name                 string   `json:"name"`
	Effect               string   `json:"effect"`
	Scopes               []string `json:"scopes,omitempty"`
	OperatorTargetFields []string `json:"operator_target_fields,omitempty"`
}

func validateManifestVersion(m Manifest) error {
	if m.Schema == "" {
		if m.Bundle != nil || m.Runtime != nil || m.UIRuntime != nil || m.Compatibility != nil || m.HostAccess != nil {
			return errors.New("bundle, runtime, ui_runtime, compatibility and host_access require manifest schema v2")
		}
		return nil
	}
	if m.Schema != ManifestSchemaV2 {
		return fmt.Errorf("unsupported manifest schema %q", m.Schema)
	}
	if m.Entrypoint != "" {
		return errors.New("manifest v2 rejects legacy entrypoint")
	}
	if m.DigestSHA256 != "" {
		return errors.New("manifest v2 rejects legacy digest_sha256")
	}
	if !pluginVersionRe.MatchString(m.Version) || strings.Contains(m.Version, "..") {
		return fmt.Errorf("manifest v2 invalid version %q", m.Version)
	}
	if m.Bundle == nil {
		return errors.New("manifest v2 bundle is required")
	}
	if m.Bundle.Format != BundleFormatTarGzip {
		return fmt.Errorf("manifest v2 bundle format must be %q", BundleFormatTarGzip)
	}
	if err := validateDigestString(m.Bundle.DigestSHA256); err != nil {
		return fmt.Errorf("manifest v2 bundle digest: %w", err)
	}
	if m.Runtime == nil {
		return errors.New("manifest v2 runtime is required")
	}
	if m.Runtime.Protocol != RuntimeProtocolStdioJSONV1 {
		return fmt.Errorf("manifest v2 runtime protocol must be %q", RuntimeProtocolStdioJSONV1)
	}
	if len(m.Runtime.Entrypoints) == 0 {
		return errors.New("manifest v2 requires at least one platform entrypoint")
	}
	for platform, entrypoint := range m.Runtime.Entrypoints {
		if !runtimePlatformRe.MatchString(platform) {
			return fmt.Errorf("manifest v2 invalid runtime platform %q", platform)
		}
		if !safeBundlePath(entrypoint) || !strings.HasPrefix(entrypoint, "bin/") {
			return fmt.Errorf("manifest v2 invalid runtime entrypoint %q", entrypoint)
		}
	}
	if m.UIRuntime != nil {
		if m.UIRuntime.Mode != UIRuntimeModeSandbox {
			return fmt.Errorf("manifest v2 ui runtime mode must be %q", UIRuntimeModeSandbox)
		}
		if !safeBundlePath(m.UIRuntime.Entrypoint) || !strings.HasPrefix(m.UIRuntime.Entrypoint, "ui/") {
			return fmt.Errorf("manifest v2 invalid ui entrypoint %q", m.UIRuntime.Entrypoint)
		}
		if path.Ext(m.UIRuntime.Entrypoint) != ".html" {
			return errors.New("manifest v2 ui entrypoint must be an .html document")
		}
		if m.UIRuntime.BridgeVersion != UIBridgeVersion1 {
			return fmt.Errorf("manifest v2 ui bridge version must be %q", UIBridgeVersion1)
		}
	}
	if m.Compatibility == nil {
		return errors.New("manifest v2 compatibility is required")
	}
	if !boundedContractValue(m.Compatibility.Server) ||
		!boundedContractValue(m.Compatibility.DashboardHost) ||
		!boundedContractValue(m.Compatibility.RuntimeProtocol) {
		return errors.New("manifest v2 compatibility fields must be printable non-empty values")
	}
	if err := validateHostAccess(m); err != nil {
		return err
	}
	return nil
}

func validateHostAccess(m Manifest) error {
	if m.HostAccess == nil {
		return nil
	}
	hasRPCCall := false
	for _, capability := range m.Capabilities {
		if capability == "rpc:call" {
			hasRPCCall = true
			break
		}
	}
	if len(m.HostAccess.RPC) > 0 && !hasRPCCall {
		return errors.New("manifest v2 host_access.rpc requires rpc:call capability")
	}
	seenServices := map[string]bool{}
	for _, dependency := range m.HostAccess.RPC {
		owner, suffix, ok := strings.Cut(dependency.Service, "/")
		if !ok || !validPluginID(owner) || !pluginServiceSuffixRe.MatchString(suffix) {
			return fmt.Errorf("manifest v2 invalid host_access rpc service %q", dependency.Service)
		}
		if owner == m.ID {
			return fmt.Errorf("manifest v2 host_access rpc service %q is owned by the caller", dependency.Service)
		}
		if seenServices[dependency.Service] {
			return fmt.Errorf("manifest v2 duplicate host_access rpc service %q", dependency.Service)
		}
		seenServices[dependency.Service] = true
		if len(dependency.Methods) == 0 {
			return fmt.Errorf("manifest v2 host_access rpc service %q requires methods", dependency.Service)
		}
		seenMethods := map[string]bool{}
		for _, method := range dependency.Methods {
			if !pluginMethodRe.MatchString(method) {
				return fmt.Errorf("manifest v2 host_access rpc service %q has invalid method %q", dependency.Service, method)
			}
			if seenMethods[method] {
				return fmt.Errorf("manifest v2 host_access rpc service %q has duplicate method %q", dependency.Service, method)
			}
			seenMethods[method] = true
		}
	}
	return nil
}

func manifestArtifactDigest(m Manifest) string {
	if m.Schema == ManifestSchemaV2 && m.Bundle != nil {
		return m.Bundle.DigestSHA256
	}
	return m.DigestSHA256
}

func validateDigestString(value string) error {
	if len(value) != 64 {
		return fmt.Errorf("invalid sha256 digest %q", value)
	}
	for _, ch := range value {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return fmt.Errorf("invalid sha256 digest %q", value)
		}
	}
	return nil
}

func safeBundlePath(value string) bool {
	if value == "" || hasControl(value) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return false
	}
	cleaned := path.Clean(value)
	return cleaned == value && cleaned != "." && cleaned != ".." && !strings.HasPrefix(cleaned, "../")
}

func boundedContractValue(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= 128 && !hasControl(value)
}
