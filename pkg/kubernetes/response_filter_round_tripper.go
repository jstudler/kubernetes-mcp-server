package kubernetes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
)

const defaultMaskValue = "[MASK]"

// compiledMaskRule is a pre-compiled version of api.MaskRule.
type compiledMaskRule struct {
	kinds []string
	paths []string
	regex *regexp.Regexp
}

// isKindOnly returns true when the rule has only kinds (no paths, no regex),
// meaning the entire matching resource should be masked.
func (r *compiledMaskRule) isKindOnly() bool {
	return len(r.kinds) > 0 && len(r.paths) == 0 && r.regex == nil
}

// ResponseFilterRoundTripper intercepts HTTP responses from the Kubernetes API
// and applies configurable data masking rules before the response reaches the
// MCP output pipeline.
type ResponseFilterRoundTripper struct {
	delegate      http.RoundTripper
	maskValue     string
	kindOnlyRules []compiledMaskRule // kinds only → mask entire resource
	fieldRules    []compiledMaskRule // paths (+ optional kinds, + optional regex) → mask field values
	regexRules    []compiledMaskRule // regex without paths (+ optional kinds) → mask string values
	// kindScoped is true when at least one rule is limited to specific kinds, in
	// which case the kind has to be resolved from the request URL.
	kindScoped         bool
	restMapperProvider func() meta.RESTMapper
	apiPathPrefix      string
}

// ResponseFilterConfig configures the ResponseFilterRoundTripper.
type ResponseFilterConfig struct {
	Delegate  http.RoundTripper
	MaskRules []api.MaskRule
	MaskValue string
	// RestMapperProvider resolves the request URL to a Kind for kind-scoped rules.
	// Evaluated lazily because the mapper does not exist yet when the transport is wrapped.
	RestMapperProvider func() meta.RESTMapper
	// HostURL is the Kubernetes API server URL, used to strip a proxy path prefix.
	HostURL string
}

// NewResponseFilterRoundTripper creates a new ResponseFilterRoundTripper.
// Returns (nil, nil) if no rules are provided.
// Returns an error if a rule sets none of kinds, paths and regex, or has an
// invalid regex pattern.
func NewResponseFilterRoundTripper(cfg ResponseFilterConfig) (*ResponseFilterRoundTripper, error) {
	if len(cfg.MaskRules) == 0 {
		return nil, nil
	}

	maskValue := cfg.MaskValue
	if maskValue == "" {
		maskValue = defaultMaskValue
	}

	var apiPathPrefix string
	if cfg.HostURL != "" {
		if hostURL, err := url.Parse(cfg.HostURL); err == nil {
			apiPathPrefix = hostURL.Path
		}
	}

	rt := &ResponseFilterRoundTripper{
		delegate:           cfg.Delegate,
		maskValue:          maskValue,
		restMapperProvider: cfg.RestMapperProvider,
		apiPathPrefix:      apiPathPrefix,
	}

	for i, rule := range cfg.MaskRules {
		// Validate: at least one field must be set
		if len(rule.Kinds) == 0 && len(rule.Paths) == 0 && rule.Regex == "" {
			return nil, fmt.Errorf("mask_rules[%d]: at least one of kinds, paths, or regex must be set", i)
		}

		compiled := compiledMaskRule{
			kinds: rule.Kinds,
			paths: rule.Paths,
		}
		if rule.Regex != "" {
			re, err := regexp.Compile(rule.Regex)
			if err != nil {
				return nil, fmt.Errorf("mask_rules[%d]: invalid regex %q: %w", i, rule.Regex, err)
			}
			compiled.regex = re
		}
		if len(compiled.kinds) > 0 {
			rt.kindScoped = true
		}

		switch {
		case compiled.isKindOnly():
			rt.kindOnlyRules = append(rt.kindOnlyRules, compiled)
		case len(compiled.paths) > 0:
			// Rules with paths go to fieldRules (handles kinds+paths, paths only, paths+regex)
			rt.fieldRules = append(rt.fieldRules, compiled)
		default:
			// Regex without paths, optionally scoped by kinds
			rt.regexRules = append(rt.regexRules, compiled)
		}
	}
	return rt, nil
}

func (rt *ResponseFilterRoundTripper) WrappedRoundTripper() http.RoundTripper {
	return rt.delegate
}

func (rt *ResponseFilterRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.delegate.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Only filter successful JSON responses
	if resp.Body == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, nil
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "json") {
		return resp, nil
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return resp, err
	}

	filtered := rt.filterResponseBody(body, rt.kindForRequest(req))

	resp.Body = io.NopCloser(bytes.NewReader(filtered))
	resp.ContentLength = int64(len(filtered))
	return resp, nil
}

// kindForRequest resolves the resource Kind addressed by the request URL.
// Returns "" when the request is not a resource request or the kind cannot be
// resolved. Table responses carry no usable kind, so this is the only way to
// scope rules for them.
func (rt *ResponseFilterRoundTripper) kindForRequest(req *http.Request) string {
	if !rt.kindScoped || rt.restMapperProvider == nil {
		return ""
	}
	// Discovery endpoints are not resource requests, which also keeps the
	// RESTMapper lookup below from recursing through this round tripper.
	gvr, ok := parseURLToGVR(stripAPIPathPrefix(req.URL.Path, rt.apiPathPrefix))
	if !ok {
		return ""
	}
	restMapper := rt.restMapperProvider()
	if restMapper == nil {
		return ""
	}
	gvk, err := restMapper.KindFor(gvr)
	if err != nil {
		return ""
	}
	return gvk.Kind
}

// filterResponseBody applies kind-only rules, field rules, then regex rules.
// requestKind is the Kind resolved from the request URL, used wherever the
// response payload itself does not carry a usable kind.
func (rt *ResponseFilterRoundTripper) filterResponseBody(body []byte, requestKind string) []byte {
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		// Not a JSON object: fall back to a raw replacement, which can only
		// honor rules that are neither kind- nor path-scoped.
		return rt.applyRegexRulesRaw(body)
	}

	scopes := documentScopes(obj, requestKind)
	modified := false

	// Apply kind-only rules (mask entire resources)
	if len(rt.kindOnlyRules) > 0 {
		modified = rt.applyKindOnlyRules(scopes) || modified
	}

	// Apply field-based rules (kinds+paths, paths only, paths+regex)
	if len(rt.fieldRules) > 0 {
		modified = rt.applyFieldRules(scopes) || modified
	}

	// Apply regex rules without paths (kinds+regex, regex only)
	if len(rt.regexRules) > 0 {
		modified = rt.applyRegexRules(scopes) || modified
	}

	if modified {
		if result, err := json.Marshal(obj); err == nil {
			return result
		}
	}
	return body
}

// documentScope is one masking unit of a response document: the kind its values
// have to be matched against, the resource objects it contains, and, for Table
// responses, the printed row cells.
type documentScope struct {
	kind string
	// kindUnresolved marks a resource payload whose kind could not be determined,
	// e.g. a Table whose request URL maps to no known resource. Kind-scoped rules
	// still apply to it so that masking fails closed.
	kindUnresolved bool
	objects        []map[string]any
	cells          []any
}

// matchesKinds reports whether a rule scoped to ruleKinds applies to this scope.
func (s documentScope) matchesKinds(ruleKinds []string) bool {
	return s.kindUnresolved || matchesKinds(ruleKinds, s.kind)
}

// documentScopes splits a response document into maskable scopes, handling
// single resources, typed lists (e.g. SecretList), generic Lists, and Tables.
func documentScopes(obj map[string]any, requestKind string) []documentScope {
	kind, _ := obj["kind"].(string)

	if kind == "Table" {
		rows, _ := obj["rows"].([]any)
		scopes := make([]documentScope, 0, len(rows))
		for _, row := range rows {
			rowObj, ok := row.(map[string]any)
			if !ok {
				continue
			}
			rowObject, _ := rowObj["object"].(map[string]any)
			rowKind, _ := rowObject["kind"].(string)
			scope := documentScope{}
			scope.kind, scope.kindUnresolved = effectiveKind(rowKind, requestKind, true)
			if rowObject != nil {
				scope.objects = append(scope.objects, rowObject)
			}
			// The values the model actually sees are the printed cells, not the
			// row object (which is a PartialObjectMetadata by default).
			if cells, ok := rowObj["cells"].([]any); ok {
				scope.cells = append(scope.cells, cells)
			}
			scopes = append(scopes, scope)
		}
		return scopes
	}

	if strings.HasSuffix(kind, "List") {
		items, _ := obj["items"].([]any)
		itemKind := strings.TrimSuffix(kind, "List")
		scopes := make([]documentScope, 0, len(items))
		for _, item := range items {
			itemObj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			k, _ := itemObj["kind"].(string)
			if k == "" {
				k = itemKind
			}
			scope := documentScope{objects: []map[string]any{itemObj}}
			scope.kind, scope.kindUnresolved = effectiveKind(k, requestKind, true)
			scopes = append(scopes, scope)
		}
		return scopes
	}

	scope := documentScope{objects: []map[string]any{obj}}
	scope.kind, scope.kindUnresolved = effectiveKind(kind, requestKind, kind != "")
	return []documentScope{scope}
}

// effectiveKind resolves the kind a scope has to be matched against, falling
// back to the kind resolved from the request URL whenever the payload kind does
// not identify the underlying resource. The second return value reports that the
// kind stayed unknown, which makes kind-scoped rules apply anyway.
// isResource tells apart a resource whose kind is merely unknown from a payload
// that is no resource at all (e.g. /version), which kind-scoped rules never match.
func effectiveKind(payloadKind, requestKind string, isResource bool) (string, bool) {
	switch payloadKind {
	case "", "Table", "List", "PartialObjectMetadata", "PartialObjectMetadataList":
		if requestKind != "" {
			return requestKind, false
		}
		return payloadKind, isResource
	}
	return payloadKind, false
}

// applyKindOnlyRules masks entire resources when only kinds are specified.
// Table cells are left untouched so masked rows remain identifiable.
func (rt *ResponseFilterRoundTripper) applyKindOnlyRules(scopes []documentScope) bool {
	modified := false
	for _, scope := range scopes {
		for _, rule := range rt.kindOnlyRules {
			if !scope.matchesKinds(rule.kinds) {
				continue
			}
			for _, obj := range scope.objects {
				rt.maskEntireResource(obj)
				modified = true
			}
			break
		}
	}
	return modified
}

// maskEntireResource replaces all non-identity fields in a resource with the mask value.
// Preserves apiVersion, kind, and metadata so the resource is still identifiable.
func (rt *ResponseFilterRoundTripper) maskEntireResource(obj map[string]any) {
	for key := range obj {
		switch key {
		case "apiVersion", "kind", "metadata":
			// preserve identity fields
		default:
			obj[key] = rt.maskValue
		}
	}
}

// applyFieldRules masks the configured paths, optionally scoped by kinds and
// optionally limited to regex matches within the field values.
// Paths only address resource objects; Table cells have no addressable paths.
func (rt *ResponseFilterRoundTripper) applyFieldRules(scopes []documentScope) bool {
	modified := false
	for _, scope := range scopes {
		for _, rule := range rt.fieldRules {
			if !scope.matchesKinds(rule.kinds) {
				continue
			}
			for _, obj := range scope.objects {
				for _, path := range rule.paths {
					if rule.regex != nil {
						rt.maskPathWithRegex(obj, path, rule.regex)
					} else {
						rt.maskPath(obj, path)
					}
					modified = true
				}
			}
		}
	}
	return modified
}

// applyRegexRules applies regex rules that have no paths to every string value
// of the matching scopes, including Table cells.
func (rt *ResponseFilterRoundTripper) applyRegexRules(scopes []documentScope) bool {
	modified := false
	for _, scope := range scopes {
		for _, rule := range rt.regexRules {
			if !scope.matchesKinds(rule.kinds) {
				continue
			}
			for _, obj := range scope.objects {
				modified = rt.maskStringValues(obj, rule.regex) || modified
			}
			for _, cells := range scope.cells {
				modified = rt.maskStringValues(cells, rule.regex) || modified
			}
		}
	}
	return modified
}

// applyRegexRulesRaw is the fallback for responses that are not a JSON object.
// Kind-scoped rules are applied too: there is no kind to match against, and
// masking fails closed.
func (rt *ResponseFilterRoundTripper) applyRegexRulesRaw(body []byte) []byte {
	for _, rule := range rt.regexRules {
		body = rule.regex.ReplaceAll(body, []byte(rt.maskValue))
	}
	return body
}

// maskStringValues replaces regex matches in every string value reachable from v.
// Map keys are never rewritten, so the JSON structure always stays intact.
func (rt *ResponseFilterRoundTripper) maskStringValues(v any, regex *regexp.Regexp) bool {
	modified := false
	switch t := v.(type) {
	case map[string]any:
		for key, val := range t {
			if s, ok := val.(string); ok {
				if masked := regex.ReplaceAllString(s, rt.maskValue); masked != s {
					t[key] = masked
					modified = true
				}
				continue
			}
			modified = rt.maskStringValues(val, regex) || modified
		}
	case []any:
		for i, val := range t {
			if s, ok := val.(string); ok {
				if masked := regex.ReplaceAllString(s, rt.maskValue); masked != s {
					t[i] = masked
					modified = true
				}
				continue
			}
			modified = rt.maskStringValues(val, regex) || modified
		}
	}
	return modified
}

// matchesKinds returns true if the resource kind matches any of the rule's kinds.
// An empty kinds slice matches everything.
func matchesKinds(ruleKinds []string, resourceKind string) bool {
	if len(ruleKinds) == 0 {
		return true
	}
	for _, k := range ruleKinds {
		if k == "*" || k == resourceKind {
			return true
		}
	}
	return false
}

// maskPath masks values at a dot-separated path within an object.
// Supports "*" as a wildcard to mask all values in a map at that level.
// Handles map keys that contain dots (e.g., Kubernetes annotation keys like
// "kubectl.kubernetes.io/last-applied-configuration") by trying progressively
// longer key segments when a simple lookup fails.
func (rt *ResponseFilterRoundTripper) maskPath(obj map[string]any, path string) {
	parts := strings.Split(path, ".")
	rt.maskPathRecursive(obj, parts)
}

func (rt *ResponseFilterRoundTripper) maskPathRecursive(current any, parts []string) {
	if len(parts) == 0 {
		return
	}

	head := parts[0]
	rest := parts[1:]

	switch v := current.(type) {
	case map[string]any:
		if head == "*" {
			if len(rest) == 0 {
				// Wildcard at leaf: mask all values in this map
				for key := range v {
					v[key] = rt.maskValue
				}
			} else {
				// Wildcard at intermediate level: recurse into all values
				for _, val := range v {
					rt.maskPathRecursive(val, rest)
				}
			}
			return
		}
		// Try exact key match first
		if val, ok := v[head]; ok {
			if len(rest) == 0 {
				v[head] = rt.maskValue
			} else {
				rt.maskPathRecursive(val, rest)
			}
			return
		}
		// Key not found — try joining progressively more segments to handle
		// map keys containing dots (e.g., annotation keys like
		// "kubectl.kubernetes.io/last-applied-configuration").
		for i := 1; i < len(rest)+1; i++ {
			candidate := strings.Join(parts[:i+1], ".")
			if val, ok := v[candidate]; ok {
				remaining := parts[i+1:]
				if len(remaining) == 0 {
					v[candidate] = rt.maskValue
				} else {
					rt.maskPathRecursive(val, remaining)
				}
				return
			}
		}
	case []any:
		// Apply to all items in the array
		for _, item := range v {
			rt.maskPathRecursive(item, parts)
		}
	}
}

// maskPathWithRegex applies a regex replacement to string values at a dot-separated path.
// Only string values are affected — non-string values are left unchanged.
func (rt *ResponseFilterRoundTripper) maskPathWithRegex(obj map[string]any, path string, regex *regexp.Regexp) {
	parts := strings.Split(path, ".")
	rt.maskPathWithRegexRecursive(obj, parts, regex)
}

func (rt *ResponseFilterRoundTripper) maskPathWithRegexRecursive(current any, parts []string, regex *regexp.Regexp) {
	if len(parts) == 0 {
		return
	}

	head := parts[0]
	rest := parts[1:]

	switch v := current.(type) {
	case map[string]any:
		if head == "*" {
			if len(rest) == 0 {
				// Wildcard at leaf: apply regex to all string values
				for key, val := range v {
					if s, ok := val.(string); ok {
						v[key] = regex.ReplaceAllString(s, rt.maskValue)
					}
				}
			} else {
				// Wildcard at intermediate level: recurse into all values
				for _, val := range v {
					rt.maskPathWithRegexRecursive(val, rest, regex)
				}
			}
			return
		}
		// Try exact key match first
		if val, ok := v[head]; ok {
			if len(rest) == 0 {
				if s, ok := val.(string); ok {
					v[head] = regex.ReplaceAllString(s, rt.maskValue)
				}
			} else {
				rt.maskPathWithRegexRecursive(val, rest, regex)
			}
			return
		}
		// Dotted key fallback
		for i := 1; i < len(rest)+1; i++ {
			candidate := strings.Join(parts[:i+1], ".")
			if val, ok := v[candidate]; ok {
				remaining := parts[i+1:]
				if len(remaining) == 0 {
					if s, ok := val.(string); ok {
						v[candidate] = regex.ReplaceAllString(s, rt.maskValue)
					}
				} else {
					rt.maskPathWithRegexRecursive(val, remaining, regex)
				}
				return
			}
		}
	case []any:
		// Apply to all items in the array
		for _, item := range v {
			rt.maskPathWithRegexRecursive(item, parts, regex)
		}
	}
}
