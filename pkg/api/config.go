package api

import (
	"slices"
	"sort"
	"strings"
)

const (
	ClusterProviderKubeConfig = "kubeconfig"
	ClusterProviderInCluster  = "in-cluster"
	ClusterProviderDisabled   = "disabled"
	ClusterProviderKcp        = "kcp"
)

// ClusterAuthMode constants define how the MCP server authenticates to the cluster.
const (
	// ClusterAuthPassthrough passes the OAuth token to the cluster.
	// If token exchange is configured (token_exchange_strategy or sts_audience),
	// the token is exchanged first before being passed through.
	ClusterAuthPassthrough = "passthrough"

	// ClusterAuthKubeconfig uses kubeconfig credentials (e.g., ServiceAccount token).
	// Use when cluster auth is separate from MCP client auth.
	ClusterAuthKubeconfig = "kubeconfig"
)

// ClusterAuthProvider provides configuration for how the MCP server authenticates to clusters.
type ClusterAuthProvider interface {
	// GetClusterAuthMode returns the raw cluster authentication mode from config.
	// Returns empty string if not explicitly set.
	GetClusterAuthMode() string
	// ResolveClusterAuthMode returns the effective cluster auth mode.
	// If explicitly set, returns that value. Otherwise auto-detects based on require_oauth.
	ResolveClusterAuthMode() string
}

type ClusterProvider interface {
	// GetClusterProviderStrategy returns the cluster provider strategy (if configured).
	GetClusterProviderStrategy() string
	// GetKubeConfigPath returns the path to the kubeconfig file (if configured).
	GetKubeConfigPath() string
}

// ExtendedConfig is the interface that all configuration extensions must implement.
// Each extended config manager registers a factory function to parse its config from TOML primitives
type ExtendedConfig interface {
	// Validate validates the extended configuration.  Returns an error if the configuration is invalid.
	Validate() error
}

type ExtendedConfigProvider interface {
	// GetProviderConfig returns the extended configuration for the given provider strategy.
	// The boolean return value indicates whether the configuration was found.
	GetProviderConfig(strategy string) (ExtendedConfig, bool)
	// GetToolsetConfig returns the extended configuration for the given toolset name.
	// The boolean return value indicates whether the configuration was found.
	GetToolsetConfig(name string) (ExtendedConfig, bool)
}

type GroupVersionKind struct {
	Group   string `json:"group" toml:"group"`
	Version string `json:"version" toml:"version"`
	Kind    string `json:"kind,omitempty" toml:"kind,omitempty"`
}

type DeniedResourcesProvider interface {
	// GetDeniedResources returns a list of GroupVersionKinds that are denied.
	GetDeniedResources() []GroupVersionKind
}

type StsConfigProvider interface {
	GetStsClientId() string
	GetStsClientSecret() string
	GetStsAudience() string
	GetStsScopes() []string
	GetStsStrategy() string
	GetStsAuthStyle() string
	GetStsClientCertFile() string
	GetStsClientKeyFile() string
	GetStsFederatedTokenFile() string
}

// CertificateAuthorityProvider provides access to the top-level certificate_authority
// TLS setting. It is a general OAuth/TLS option (also consumed by pkg/oauth) rather
// than an STS-specific one, so it is kept separate from StsConfigProvider.
type CertificateAuthorityProvider interface {
	GetCertificateAuthority() string
}

// ValidationEnabledProvider provides access to validation enabled setting.
type ValidationEnabledProvider interface {
	IsValidationEnabled() bool
}

// TargetCompatibilityToolFiltersEnabledProvider provides access to target compatibility tool filters setting.
type TargetCompatibilityToolFiltersEnabledProvider interface {
	IsTargetCompatibilityToolFiltersEnabled() bool
}

// RequireTLSProvider provides access to require_tls setting.
type RequireTLSProvider interface {
	IsRequireTLS() bool
}

// TLSConfigProvider provides access to global TLS min version and cipher suite settings.
// Values include TLS_MIN_VERSION and TLS_CIPHER_SUITES env overrides when set.
type TLSConfigProvider interface {
	GetTLSMinVersionConfig() string
	GetTLSCipherSuitesConfig() []string
}

// RequireOAuthProvider provides access to require_oauth setting.
type RequireOAuthProvider interface {
	IsRequireOAuth() bool
}

// MaskRule defines a data masking rule for Kubernetes API responses.
// At least one of Kinds, Paths, or Regex must be set. The supported combinations are:
//
//   - Kinds only: the entire resource is masked (all non-identity fields replaced) for matching kinds.
//   - Kinds + Paths: only the specified field paths are masked within matching kinds.
//   - Kinds + Regex: the regex is applied to every string value of matching kinds.
//   - Paths only: the specified field paths are masked regardless of kind.
//   - Regex only: the regex is applied to every string value regardless of kind.
//   - Paths + Regex: the regex is applied only to the values at the specified field paths.
//
// Kubernetes Table responses (list_output = "table") carry no resource kind, so the kind is
// resolved from the request URL instead. Table rows only embed a PartialObjectMetadata, which
// means Paths outside of metadata cannot be masked in a Table; list operations for the affected
// kinds therefore fall back to YAML output. See TableIncompatibleKinds.
type MaskRule struct {
	// Kinds lists the Kubernetes resource kinds this rule applies to (e.g., ["Secret"], ["Pod", "Deployment"]).
	// If empty, the rule applies to all resource kinds.
	Kinds []string `json:"kinds,omitempty" toml:"kinds,omitempty"`
	// Paths lists dot-separated field paths whose values should be masked.
	// When Regex is not set, matched values are replaced with the configured mask value.
	// When Regex is set, only regex matches within the field values are replaced.
	// Supports map wildcards: "data.*" masks all values under "data".
	// Examples: "data.*", "stringData.*", "spec.containers.env.value"
	Paths []string `json:"paths,omitempty" toml:"paths,omitempty"`
	// Regex is a regular expression pattern. All matches are replaced with the configured mask value.
	// Without Paths: applied to every string value of the response, including Table row cells.
	// With Paths: applied only to the string values at the matched field paths.
	Regex string `json:"regex,omitempty" toml:"regex,omitempty"`
}

// TableIncompatibleKinds reports the kinds whose list operations cannot be served as a
// Kubernetes Table without leaking data the rules are meant to mask. Table rows only embed a
// PartialObjectMetadata, so a rule with a path outside of "metadata" has nothing to match
// against. Returns allKinds=true when such a rule is not scoped to specific kinds.
func TableIncompatibleKinds(rules []MaskRule) (kinds []string, allKinds bool) {
	seen := make(map[string]bool)
	for _, rule := range rules {
		tableSafe := true
		for _, path := range rule.Paths {
			if head, _, _ := strings.Cut(path, "."); head != "metadata" {
				tableSafe = false
				break
			}
		}
		if tableSafe {
			continue
		}
		if len(rule.Kinds) == 0 {
			allKinds = true
			continue
		}
		for _, kind := range rule.Kinds {
			if kind == "*" {
				allKinds = true
				continue
			}
			if !seen[kind] {
				seen[kind] = true
				kinds = append(kinds, kind)
			}
		}
	}
	sort.Strings(kinds)
	return kinds, allKinds
}

// IsTableOutputAllowed reports whether list operations for the given kind may be served as a
// Kubernetes Table under the configured mask rules.
func IsTableOutputAllowed(rules []MaskRule, kind string) bool {
	incompatible, allKinds := TableIncompatibleKinds(rules)
	if allKinds {
		return false
	}
	return !slices.Contains(incompatible, kind)
}

// ResponseFilterProvider provides access to response filtering settings.
type ResponseFilterProvider interface {
	GetMaskRules() []MaskRule
	GetMaskValue() string
}

type BaseConfig interface {
	ClusterAuthProvider
	ClusterProvider
	ConfirmationRulesProvider
	DeniedResourcesProvider
	ExtendedConfigProvider
	StsConfigProvider
	CertificateAuthorityProvider
	ValidationEnabledProvider
	TargetCompatibilityToolFiltersEnabledProvider
	RequireTLSProvider
	TLSConfigProvider
	RequireOAuthProvider
	ResponseFilterProvider
}
