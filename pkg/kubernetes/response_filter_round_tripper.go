package kubernetes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

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
	regexRules    []compiledMaskRule // regex only → apply to entire serialized response
}

// ResponseFilterConfig configures the ResponseFilterRoundTripper.
type ResponseFilterConfig struct {
	Delegate  http.RoundTripper
	MaskRules []api.MaskRule
	MaskValue string
}

// NewResponseFilterRoundTripper creates a new ResponseFilterRoundTripper.
// Returns (nil, nil) if no rules are provided.
// Returns an error if a rule has an invalid combination (Kinds + Regex without Paths)
// or an invalid regex pattern.
func NewResponseFilterRoundTripper(cfg ResponseFilterConfig) (*ResponseFilterRoundTripper, error) {
	if len(cfg.MaskRules) == 0 {
		return nil, nil
	}

	maskValue := cfg.MaskValue
	if maskValue == "" {
		maskValue = defaultMaskValue
	}

	rt := &ResponseFilterRoundTripper{
		delegate:  cfg.Delegate,
		maskValue: maskValue,
	}

	for i, rule := range cfg.MaskRules {
		// Validate: Kinds + Regex without Paths is not supported
		if len(rule.Kinds) > 0 && rule.Regex != "" && len(rule.Paths) == 0 {
			return nil, fmt.Errorf("mask_rules[%d]: combining kinds with regex without paths is not supported (Kubernetes Table responses do not carry the resource kind)", i)
		}
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

		if compiled.isKindOnly() {
			rt.kindOnlyRules = append(rt.kindOnlyRules, compiled)
		} else if len(compiled.paths) > 0 {
			// Rules with paths go to fieldRules (handles kinds+paths, paths only, paths+regex)
			rt.fieldRules = append(rt.fieldRules, compiled)
		} else if compiled.regex != nil {
			// Regex-only rules (no kinds, no paths)
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

	filtered := rt.filterResponseBody(body)

	resp.Body = io.NopCloser(bytes.NewReader(filtered))
	resp.ContentLength = int64(len(filtered))
	return resp, nil
}

// filterResponseBody applies kind-only rules, field rules, then regex rules.
func (rt *ResponseFilterRoundTripper) filterResponseBody(body []byte) []byte {
	var obj map[string]any
	parsed := json.Unmarshal(body, &obj) == nil

	if parsed {
		modified := false

		// Apply kind-only rules (mask entire resources)
		if len(rt.kindOnlyRules) > 0 {
			modified = rt.applyKindOnlyRules(obj) || modified
		}

		// Apply field-based rules (kinds+paths, paths only, paths+regex)
		if len(rt.fieldRules) > 0 {
			rt.applyFieldRules(obj)
			modified = true
		}

		if modified {
			if result, err := json.Marshal(obj); err == nil {
				body = result
			}
		}
	}

	// Apply regex-only rules against entire serialized JSON
	if len(rt.regexRules) > 0 {
		body = rt.applyRegexRules(body)
	}

	return body
}

// applyKindOnlyRules masks entire resources when only kinds are specified.
// Returns true if any modification was made.
func (rt *ResponseFilterRoundTripper) applyKindOnlyRules(obj map[string]any) bool {
	kind, _ := obj["kind"].(string)

	if strings.HasSuffix(kind, "List") || kind == "List" {
		return rt.applyKindOnlyToList(obj, strings.TrimSuffix(kind, "List"))
	}
	if kind == "Table" {
		return rt.applyKindOnlyToTable(obj)
	}

	for _, rule := range rt.kindOnlyRules {
		if matchesKinds(rule.kinds, kind) {
			rt.maskEntireResource(obj)
			return true
		}
	}
	return false
}

// applyKindOnlyToList masks entire items in a list when they match kind-only rules.
func (rt *ResponseFilterRoundTripper) applyKindOnlyToList(obj map[string]any, itemKind string) bool {
	items, ok := obj["items"].([]any)
	if !ok {
		return false
	}
	modified := false
	for _, item := range items {
		itemObj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		k, _ := itemObj["kind"].(string)
		if k == "" {
			k = itemKind
		}
		for _, rule := range rt.kindOnlyRules {
			if matchesKinds(rule.kinds, k) {
				rt.maskEntireResource(itemObj)
				modified = true
				break
			}
		}
	}
	return modified
}

// applyKindOnlyToTable masks entire Table row objects when they match kind-only rules.
func (rt *ResponseFilterRoundTripper) applyKindOnlyToTable(obj map[string]any) bool {
	rows, ok := obj["rows"].([]any)
	if !ok {
		return false
	}
	modified := false
	for _, row := range rows {
		rowObj, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowObject, ok := rowObj["object"].(map[string]any)
		if !ok {
			continue
		}
		k, _ := rowObject["kind"].(string)
		for _, rule := range rt.kindOnlyRules {
			if matchesKinds(rule.kinds, k) {
				rt.maskEntireResource(rowObject)
				modified = true
				break
			}
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

// applyFieldRules applies field masking to a parsed JSON object.
// Handles rules with paths (optionally scoped by kinds, optionally with regex).
// Handles single resources, typed lists (e.g. SecretList), generic Lists, and Tables.
func (rt *ResponseFilterRoundTripper) applyFieldRules(obj map[string]any) {
	kind, _ := obj["kind"].(string)

	// Check if this is a list type
	if strings.HasSuffix(kind, "List") || kind == "List" {
		rt.applyFieldRulesToList(obj, strings.TrimSuffix(kind, "List"))
		return
	}
	if kind == "Table" {
		rt.applyFieldRulesToTable(obj)
		return
	}

	// Single resource
	for _, rule := range rt.fieldRules {
		if matchesKinds(rule.kinds, kind) {
			for _, path := range rule.paths {
				if rule.regex != nil {
					rt.maskPathWithRegex(obj, path, rule.regex)
				} else {
					rt.maskPath(obj, path)
				}
			}
		}
	}
}

// applyFieldRulesToList applies field rules to items in a list response.
func (rt *ResponseFilterRoundTripper) applyFieldRulesToList(obj map[string]any, itemKind string) {
	items, ok := obj["items"].([]any)
	if !ok {
		return
	}
	for _, item := range items {
		itemObj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		// Determine the kind of the item — prefer item's own kind, fall back to list-derived kind
		k, _ := itemObj["kind"].(string)
		if k == "" {
			k = itemKind
		}
		for _, rule := range rt.fieldRules {
			if matchesKinds(rule.kinds, k) {
				for _, path := range rule.paths {
					if rule.regex != nil {
						rt.maskPathWithRegex(itemObj, path, rule.regex)
					} else {
						rt.maskPath(itemObj, path)
					}
				}
			}
		}
	}
}

// applyFieldRulesToTable applies field rules to Table rows (rows[].object).
func (rt *ResponseFilterRoundTripper) applyFieldRulesToTable(obj map[string]any) {
	rows, ok := obj["rows"].([]any)
	if !ok {
		return
	}
	for _, row := range rows {
		rowObj, ok := row.(map[string]any)
		if !ok {
			continue
		}
		rowObject, ok := rowObj["object"].(map[string]any)
		if !ok {
			continue
		}
		k, _ := rowObject["kind"].(string)
		for _, rule := range rt.fieldRules {
			if matchesKinds(rule.kinds, k) {
				for _, path := range rule.paths {
					if rule.regex != nil {
						rt.maskPathWithRegex(rowObject, path, rule.regex)
					} else {
						rt.maskPath(rowObject, path)
					}
				}
			}
		}
	}
}

// applyRegexRules applies regex-only rules to the entire serialized response.
// These rules have no kind scoping (rejected at validation time).
func (rt *ResponseFilterRoundTripper) applyRegexRules(body []byte) []byte {
	for _, rule := range rt.regexRules {
		body = rule.regex.ReplaceAll(body, []byte(rt.maskValue))
	}
	return body
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
