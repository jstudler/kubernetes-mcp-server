package kubernetes

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/suite"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/containers/kubernetes-mcp-server/pkg/api"
)

type ResponseFilterRoundTripperSuite struct {
	suite.Suite
}

func TestResponseFilterRoundTripper(t *testing.T) {
	suite.Run(t, new(ResponseFilterRoundTripperSuite))
}

func (s *ResponseFilterRoundTripperSuite) newMockDelegate(responseBody string) *mockRoundTripper {
	called := false
	return &mockRoundTripper{
		called: &called,
		onRequest: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(responseBody))
		},
	}
}

func (s *ResponseFilterRoundTripperSuite) mustNewRT(delegate http.RoundTripper, rules []api.MaskRule) *ResponseFilterRoundTripper {
	rt, err := NewResponseFilterRoundTripper(ResponseFilterConfig{
		Delegate:  delegate,
		MaskRules: rules,
	})
	s.Require().NoError(err)
	s.Require().NotNil(rt)
	return rt
}

func (s *ResponseFilterRoundTripperSuite) mustNewRTWithMaskValue(delegate http.RoundTripper, rules []api.MaskRule, maskValue string) *ResponseFilterRoundTripper {
	rt, err := NewResponseFilterRoundTripper(ResponseFilterConfig{
		Delegate:  delegate,
		MaskRules: rules,
		MaskValue: maskValue,
	})
	s.Require().NoError(err)
	s.Require().NotNil(rt)
	return rt
}

// mustNewRTWithRestMapper builds a round tripper that can resolve the request URL to a
// Kind, which is the only way to scope rules for Table responses.
func (s *ResponseFilterRoundTripperSuite) mustNewRTWithRestMapper(delegate http.RoundTripper, rules []api.MaskRule, gvks ...schema.GroupVersionKind) *ResponseFilterRoundTripper {
	restMapper := meta.NewDefaultRESTMapper(nil)
	for _, gvk := range gvks {
		restMapper.Add(gvk, meta.RESTScopeNamespace)
	}
	rt, err := NewResponseFilterRoundTripper(ResponseFilterConfig{
		Delegate:           delegate,
		MaskRules:          rules,
		RestMapperProvider: func() meta.RESTMapper { return restMapper },
	})
	s.Require().NoError(err)
	s.Require().NotNil(rt)
	return rt
}

func (s *ResponseFilterRoundTripperSuite) TestNewResponseFilterRoundTripperReturnsNilWhenNoRules() {
	rt, err := NewResponseFilterRoundTripper(ResponseFilterConfig{
		Delegate:  nil,
		MaskRules: nil,
	})
	s.NoError(err)
	s.Nil(rt)
}

func (s *ResponseFilterRoundTripperSuite) TestNewResponseFilterRoundTripperRejectsInvalidRegex() {
	_, err := NewResponseFilterRoundTripper(ResponseFilterConfig{
		Delegate: nil,
		MaskRules: []api.MaskRule{
			{Regex: "[invalid"},
		},
	})
	s.Error(err)
	s.Contains(err.Error(), "mask_rules[0]")
}

func (s *ResponseFilterRoundTripperSuite) TestNewResponseFilterRoundTripperAcceptsKindsWithRegexWithoutPaths() {
	rt, err := NewResponseFilterRoundTripper(ResponseFilterConfig{
		Delegate: nil,
		MaskRules: []api.MaskRule{
			{Kinds: []string{"Service"}, Regex: `\d+`},
		},
	})
	s.NoError(err)
	s.NotNil(rt)
}

func (s *ResponseFilterRoundTripperSuite) TestNewResponseFilterRoundTripperRejectsEmptyRule() {
	_, err := NewResponseFilterRoundTripper(ResponseFilterConfig{
		Delegate: nil,
		MaskRules: []api.MaskRule{
			{},
		},
	})
	s.Error(err)
	s.Contains(err.Error(), "mask_rules[0]")
	s.Contains(err.Error(), "at least one of kinds, paths, or regex must be set")
}

func (s *ResponseFilterRoundTripperSuite) TestNewResponseFilterRoundTripperAcceptsKindsWithRegexAndPaths() {
	// Kinds + Paths + Regex is valid (regex scoped to matched field values)
	rt, err := NewResponseFilterRoundTripper(ResponseFilterConfig{
		Delegate: nil,
		MaskRules: []api.MaskRule{
			{Kinds: []string{"Pod"}, Paths: []string{"status.podIP"}, Regex: `\d+\.\d+\.\d+\.\d+`},
		},
	})
	s.NoError(err)
	s.NotNil(rt)
}

func (s *ResponseFilterRoundTripperSuite) TestFieldRules() {
	secretRules := []api.MaskRule{
		{Kinds: []string{"Secret"}, Paths: []string{"data.*", "stringData.*"}},
	}

	s.Run("masks data field values in a Secret", func() {
		secret := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"my-secret","namespace":"default"},"data":{"username":"YWRtaW4=","password":"cGFzc3dvcmQ="},"type":"Opaque"}`
		rt := s.mustNewRT(s.newMockDelegate(secret), secretRules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/secrets/my-secret", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		data := result["data"].(map[string]any)
		s.Equal("[MASK]", data["username"])
		s.Equal("[MASK]", data["password"])
		s.Contains(data, "username")
		s.Contains(data, "password")
	})

	s.Run("masks stringData field values in a Secret", func() {
		secret := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"my-secret"},"stringData":{"config.yaml":"apiUrl: https://example.com\ntoken: secret123"},"type":"Opaque"}`
		rt := s.mustNewRT(s.newMockDelegate(secret), secretRules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/secrets/my-secret", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		stringData := result["stringData"].(map[string]any)
		s.Equal("[MASK]", stringData["config.yaml"])
	})

	s.Run("masks all secrets in a SecretList", func() {
		secretList := `{"apiVersion":"v1","kind":"SecretList","items":[{"apiVersion":"v1","kind":"Secret","metadata":{"name":"secret-1"},"data":{"key1":"dmFsdWUx"}},{"apiVersion":"v1","kind":"Secret","metadata":{"name":"secret-2"},"data":{"key2":"dmFsdWUy"}}]}`
		rt := s.mustNewRT(s.newMockDelegate(secretList), secretRules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/secrets", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		items := result["items"].([]any)
		s.Len(items, 2)
		for _, item := range items {
			itemMap := item.(map[string]any)
			data := itemMap["data"].(map[string]any)
			for _, v := range data {
				s.Equal("[MASK]", v)
			}
		}
	})

	s.Run("does not mask non-Secret resources", func() {
		configMap := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"my-cm"},"data":{"key":"value"}}`
		rt := s.mustNewRT(s.newMockDelegate(configMap), secretRules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/configmaps/my-cm", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		data := result["data"].(map[string]any)
		s.Equal("value", data["key"])
	})

	s.Run("preserves metadata in masked secrets", func() {
		secret := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"my-secret","namespace":"default","labels":{"app":"test"}},"data":{"token":"c2VjcmV0"},"type":"kubernetes.io/service-account-token"}`
		rt := s.mustNewRT(s.newMockDelegate(secret), secretRules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/secrets/my-secret", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		metadata := result["metadata"].(map[string]any)
		s.Equal("my-secret", metadata["name"])
		s.Equal("default", metadata["namespace"])
		s.Equal("kubernetes.io/service-account-token", result["type"])
		data := result["data"].(map[string]any)
		s.Equal("[MASK]", data["token"])
	})

	s.Run("masks env values in Pod spec", func() {
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"my-pod"},"spec":{"containers":[{"name":"app","env":[{"name":"DB_PASSWORD","value":"s3cret"},{"name":"LOG_LEVEL","value":"info"}]}]}}`
		envRules := []api.MaskRule{
			{Kinds: []string{"Pod"}, Paths: []string{"spec.containers.env.value"}},
		}
		rt := s.mustNewRT(s.newMockDelegate(pod), envRules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/pods/my-pod", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		spec := result["spec"].(map[string]any)
		containers := spec["containers"].([]any)
		container := containers[0].(map[string]any)
		envVars := container["env"].([]any)
		for _, e := range envVars {
			env := e.(map[string]any)
			s.Equal("[MASK]", env["value"], "env var %s should be masked", env["name"])
		}
	})

	s.Run("wildcard kind masks all resource types", func() {
		cm := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"my-cm"},"data":{"key":"value"}}`
		wildcardRules := []api.MaskRule{
			{Kinds: []string{"*"}, Paths: []string{"data.*"}},
		}
		rt := s.mustNewRT(s.newMockDelegate(cm), wildcardRules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/configmaps/my-cm", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		data := result["data"].(map[string]any)
		s.Equal("[MASK]", data["key"])
	})

	s.Run("masks secrets in Table format", func() {
		table := `{"kind":"Table","rows":[{"object":{"apiVersion":"v1","kind":"Secret","data":{"tok":"abc"}}}]}`
		rt := s.mustNewRT(s.newMockDelegate(table), secretRules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/secrets", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		rows := result["rows"].([]any)
		rowObj := rows[0].(map[string]any)["object"].(map[string]any)
		data := rowObj["data"].(map[string]any)
		s.Equal("[MASK]", data["tok"])
	})
}

func (s *ResponseFilterRoundTripperSuite) TestRegexRules() {
	ipv4Rule := api.MaskRule{
		Regex: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/[0-9]{1,2})?\b`,
	}
	ipv6Rule := api.MaskRule{
		Regex: `(?i)(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}|::(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4}|::)(?:/[0-9]{1,3})?`,
	}

	s.Run("masks IPv4 addresses", func() {
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"my-pod"},"status":{"podIP":"10.244.0.5","hostIP":"192.168.1.100"}}`
		rt := s.mustNewRT(s.newMockDelegate(pod), []api.MaskRule{ipv4Rule})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/pods/my-pod", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		s.NotContains(bodyStr, "10.244.0.5")
		s.NotContains(bodyStr, "192.168.1.100")
		s.Contains(bodyStr, "[MASK]")
	})

	s.Run("masks IPv4 CIDR notation", func() {
		netpol := `{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","spec":{"ingress":[{"from":[{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.0.0.0/24"]}}]}]}}`
		rt := s.mustNewRT(s.newMockDelegate(netpol), []api.MaskRule{ipv4Rule})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/apis/networking.k8s.io/v1/networkpolicies/test", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		s.NotContains(bodyStr, "10.0.0.0/8")
		s.NotContains(bodyStr, "10.0.0.0/24")
	})

	s.Run("masks IPv6 addresses", func() {
		svc := `{"apiVersion":"v1","kind":"Service","metadata":{"name":"my-svc"},"spec":{"clusterIP":"fd00::1","clusterIPs":["fd00::1","2001:db8:85a3::8a2e:370:7334"]}}`
		rt := s.mustNewRT(s.newMockDelegate(svc), []api.MaskRule{ipv6Rule})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/services/my-svc", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		s.NotContains(bodyStr, "fd00::1")
		s.NotContains(bodyStr, "2001:db8:85a3::8a2e:370:7334")
		s.Contains(bodyStr, "[MASK]")
	})

	s.Run("masks IPv6 CIDR notation", func() {
		netpol := `{"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","spec":{"ingress":[{"from":[{"ipBlock":{"cidr":"fd00::/64"}}]}]}}`
		rt := s.mustNewRT(s.newMockDelegate(netpol), []api.MaskRule{ipv6Rule})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/apis/networking.k8s.io/v1/networkpolicies/test", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		s.NotContains(bodyStr, "fd00::/64")
	})

	s.Run("masks mixed IPv4 and IPv6 addresses", func() {
		node := `{"apiVersion":"v1","kind":"Node","metadata":{"name":"node-1"},"status":{"addresses":[{"type":"InternalIP","address":"10.0.0.1"},{"type":"ExternalIP","address":"203.0.113.50"},{"type":"InternalIP","address":"fe80::1"}]}}`
		rt := s.mustNewRT(s.newMockDelegate(node), []api.MaskRule{ipv4Rule, ipv6Rule})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/nodes/node-1", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		s.NotContains(bodyStr, "10.0.0.1")
		s.NotContains(bodyStr, "203.0.113.50")
		s.NotContains(bodyStr, "fe80::1")
		s.Contains(bodyStr, "[MASK]")
	})

	s.Run("does not mask non-IP numeric patterns", func() {
		cm := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"my-cm"},"data":{"port":"8080","version":"1.2.3"}}`
		rt := s.mustNewRT(s.newMockDelegate(cm), []api.MaskRule{ipv4Rule})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/configmaps/my-cm", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		s.Contains(bodyStr, "8080")
		s.Contains(bodyStr, "1.2.3")
	})

	s.Run("does not mask map keys", func() {
		cm := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"my-cm"},"data":{"10.0.0.1":"upstream"}}`
		rt := s.mustNewRT(s.newMockDelegate(cm), []api.MaskRule{ipv4Rule})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/configmaps/my-cm", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))
		data := result["data"].(map[string]any)
		s.Contains(data, "10.0.0.1")
	})
}

// serviceTable mimics a `list_output = "table"` response: rows carry a
// PartialObjectMetadata, and the printed values live in the cells.
const serviceTable = `{
	"kind":"Table",
	"apiVersion":"meta.k8s.io/v1",
	"columnDefinitions":[{"name":"Name","type":"string"},{"name":"Cluster-IP","type":"string"},{"name":"External-IP","type":"string"}],
	"rows":[
		{
			"cells":["my-svc","10.96.0.42","203.0.113.50"],
			"object":{"kind":"PartialObjectMetadata","apiVersion":"meta.k8s.io/v1","metadata":{"name":"my-svc","namespace":"default"}}
		}
	]
}`

func (s *ResponseFilterRoundTripperSuite) TestKindScopedRegexRules() {
	ipv4Rule := api.MaskRule{
		Kinds: []string{"Service"},
		Regex: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/[0-9]{1,2})?\b`,
	}
	serviceGVK := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"}
	podGVK := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}

	s.Run("masks matching kind in a yaml (non-table) response", func() {
		svc := `{"apiVersion":"v1","kind":"Service","metadata":{"name":"my-svc"},"spec":{"clusterIP":"10.96.0.42"},"status":{"loadBalancer":{"ingress":[{"ip":"203.0.113.50"}]}}}`
		rt := s.mustNewRTWithRestMapper(s.newMockDelegate(svc), []api.MaskRule{ipv4Rule}, serviceGVK)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/services/my-svc", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		s.NotContains(bodyStr, "10.96.0.42")
		s.NotContains(bodyStr, "203.0.113.50")
		s.Contains(bodyStr, "[MASK]")
	})

	s.Run("does not mask a non-matching kind", func() {
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"my-pod"},"status":{"podIP":"10.244.0.5"}}`
		rt := s.mustNewRTWithRestMapper(s.newMockDelegate(pod), []api.MaskRule{ipv4Rule}, podGVK)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/pods/my-pod", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		s.Contains(string(body), "10.244.0.5")
	})

	s.Run("masks Table cells using the kind resolved from the request", func() {
		rt := s.mustNewRTWithRestMapper(s.newMockDelegate(serviceTable), []api.MaskRule{ipv4Rule}, serviceGVK)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/services", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		cells := result["rows"].([]any)[0].(map[string]any)["cells"].([]any)
		s.Equal("my-svc", cells[0], "non-matching cells are preserved")
		s.Equal("[MASK]", cells[1])
		s.Equal("[MASK]", cells[2])
	})

	s.Run("does not mask Table cells of a non-matching kind", func() {
		rt := s.mustNewRTWithRestMapper(s.newMockDelegate(serviceTable), []api.MaskRule{
			{Kinds: []string{"Pod"}, Regex: ipv4Rule.Regex},
		}, serviceGVK)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/services", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		s.Contains(string(body), "10.96.0.42")
	})

	s.Run("applies kind-scoped rules when the kind cannot be resolved", func() {
		rt := s.mustNewRT(s.newMockDelegate(serviceTable), []api.MaskRule{ipv4Rule})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/services", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		s.NotContains(string(body), "10.96.0.42", "masking has to fail closed")
	})

	s.Run("does not apply kind-scoped rules to payloads that are not resources", func() {
		version := `{"major":"1","minor":"31","gitVersion":"v1.31.0","buildDate":"10.96.0.42"}`
		rt := s.mustNewRT(s.newMockDelegate(version), []api.MaskRule{ipv4Rule})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/version", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		s.Contains(string(body), "10.96.0.42")
	})

	s.Run("kind-less regex rules mask Table cells without a rest mapper", func() {
		rt := s.mustNewRT(s.newMockDelegate(serviceTable), []api.MaskRule{{Regex: ipv4Rule.Regex}})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/services", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		cells := result["rows"].([]any)[0].(map[string]any)["cells"].([]any)
		s.Equal("my-svc", cells[0])
		s.Equal("[MASK]", cells[1])
		s.Equal("[MASK]", cells[2])
	})

	s.Run("masks list items using the kind resolved from the request", func() {
		list := `{"apiVersion":"v1","kind":"List","items":[{"metadata":{"name":"my-svc"},"spec":{"clusterIP":"10.96.0.42"}}]}`
		rt := s.mustNewRTWithRestMapper(s.newMockDelegate(list), []api.MaskRule{ipv4Rule}, serviceGVK)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/services", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		s.NotContains(string(body), "10.96.0.42")
	})
}

func (s *ResponseFilterRoundTripperSuite) TestKindScopedPathRulesOnTable() {
	serviceGVK := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Service"}

	s.Run("masks metadata paths in Table rows using the request kind", func() {
		table := `{"kind":"Table","rows":[{"cells":["my-svc"],"object":{"kind":"PartialObjectMetadata","metadata":{"name":"my-svc","annotations":{"secret":"hide-me"}}}}]}`
		rt := s.mustNewRTWithRestMapper(s.newMockDelegate(table), []api.MaskRule{
			{Kinds: []string{"Service"}, Paths: []string{"metadata.annotations.secret"}},
		}, serviceGVK)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/services", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		rowObject := result["rows"].([]any)[0].(map[string]any)["object"].(map[string]any)
		annotations := rowObject["metadata"].(map[string]any)["annotations"].(map[string]any)
		s.Equal("[MASK]", annotations["secret"])
	})
}

func (s *ResponseFilterRoundTripperSuite) TestCombinedRules() {
	s.Run("field and regex rules work together", func() {
		secret := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"tls-secret"},"data":{"ca.crt":"LS0tLS1...","server-ip":"MTAuMC4wLjE="},"type":"kubernetes.io/tls"}`
		rules := []api.MaskRule{
			{Kinds: []string{"Secret"}, Paths: []string{"data.*", "stringData.*"}},
			{Regex: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/[0-9]{1,2})?\b`},
		}
		rt := s.mustNewRT(s.newMockDelegate(secret), rules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/secrets/tls-secret", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		data := result["data"].(map[string]any)
		s.Equal("[MASK]", data["ca.crt"])
		s.Equal("[MASK]", data["server-ip"])
	})
}

func (s *ResponseFilterRoundTripperSuite) TestPassthroughCases() {
	rules := []api.MaskRule{
		{Kinds: []string{"Secret"}, Paths: []string{"data.*"}},
		{Regex: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`},
	}

	s.Run("passes through non-JSON responses", func() {
		called := false
		delegate := &mockRoundTripper{
			called: &called,
			onRequest: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("plain text with IP 10.0.0.1"))
			},
		}
		rt := s.mustNewRT(delegate, rules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/pods/my-pod/log", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		s.Contains(string(body), "10.0.0.1")
	})

	s.Run("passes through error responses", func() {
		called := false
		delegate := &mockRoundTripper{
			called: &called,
			onRequest: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"kind":"Status","status":"Failure","message":"secrets \"my-secret\" not found","reason":"NotFound","code":404}`))
			},
		}
		rt := s.mustNewRT(delegate, rules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/secrets/my-secret", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		s.Contains(string(body), "not found")
	})

	s.Run("passes through nil body responses", func() {
		called := false
		delegate := &mockRoundTripper{
			called: &called,
			onRequest: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
		}
		rt := s.mustNewRT(delegate, rules)

		req := httptest.NewRequest(http.MethodDelete, "http://localhost/api/v1/namespaces/default/secrets/my-secret", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)
		s.Equal(http.StatusNoContent, resp.StatusCode)
	})
}

func (s *ResponseFilterRoundTripperSuite) TestMaskPathRecursive() {
	// Create a minimal RT for direct maskPath testing
	rt := &ResponseFilterRoundTripper{maskValue: "[MASK]"}
	s.Run("nested path masking", func() {
		obj := map[string]any{
			"spec": map[string]any{
				"template": map[string]any{
					"spec": map[string]any{
						"containers": []any{
							map[string]any{
								"name": "app",
								"env": []any{
									map[string]any{"name": "SECRET", "value": "s3cret"},
									map[string]any{"name": "NORMAL", "value": "hello"},
								},
							},
						},
					},
				},
			},
		}
		rt.maskPath(obj, "spec.template.spec.containers.env.value")

		containers := obj["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["containers"].([]any)
		env := containers[0].(map[string]any)["env"].([]any)
		s.Equal("[MASK]", env[0].(map[string]any)["value"])
		s.Equal("[MASK]", env[1].(map[string]any)["value"])
		// Names are preserved
		s.Equal("SECRET", env[0].(map[string]any)["name"])
		s.Equal("NORMAL", env[1].(map[string]any)["name"])
	})

	s.Run("missing path is a no-op", func() {
		obj := map[string]any{"metadata": map[string]any{"name": "test"}}
		rt.maskPath(obj, "spec.containers.env.value")
		s.Equal("test", obj["metadata"].(map[string]any)["name"])
	})

	s.Run("wildcard at intermediate level", func() {
		obj := map[string]any{
			"data": map[string]any{
				"section1": map[string]any{"password": "s3cret", "user": "admin"},
				"section2": map[string]any{"password": "other", "user": "root"},
			},
		}
		rt.maskPath(obj, "data.*.password")

		s1 := obj["data"].(map[string]any)["section1"].(map[string]any)
		s2 := obj["data"].(map[string]any)["section2"].(map[string]any)
		s.Equal("[MASK]", s1["password"])
		s.Equal("admin", s1["user"])
		s.Equal("[MASK]", s2["password"])
		s.Equal("root", s2["user"])
	})

	s.Run("dotted annotation key", func() {
		obj := map[string]any{
			"metadata": map[string]any{
				"name": "my-deploy",
				"annotations": map[string]any{
					"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"apps/v1","kind":"Deployment","spec":{"replicas":3}}`,
					"app.kubernetes.io/name":                           "myapp",
				},
			},
		}
		rt.maskPath(obj, "metadata.annotations.kubectl.kubernetes.io/last-applied-configuration")

		annotations := obj["metadata"].(map[string]any)["annotations"].(map[string]any)
		s.Equal("[MASK]", annotations["kubectl.kubernetes.io/last-applied-configuration"])
		// Other annotations are preserved
		s.Equal("myapp", annotations["app.kubernetes.io/name"])
		// Metadata name is preserved
		s.Equal("my-deploy", obj["metadata"].(map[string]any)["name"])
	})
}

func (s *ResponseFilterRoundTripperSuite) TestKindOnlyRules() {
	s.Run("masks entire Secret resource keeping identity fields", func() {
		secret := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"my-secret","namespace":"default"},"data":{"username":"YWRtaW4=","password":"cGFzc3dvcmQ="},"type":"Opaque"}`
		rt := s.mustNewRT(s.newMockDelegate(secret), []api.MaskRule{
			{Kinds: []string{"Secret"}},
		})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/secrets/my-secret", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		s.Equal("v1", result["apiVersion"])
		s.Equal("Secret", result["kind"])
		s.Equal("my-secret", result["metadata"].(map[string]any)["name"])
		s.Equal("[MASK]", result["data"])
		s.Equal("[MASK]", result["type"])
	})

	s.Run("does not mask non-matching kind", func() {
		cm := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"my-cm"},"data":{"key":"value"}}`
		rt := s.mustNewRT(s.newMockDelegate(cm), []api.MaskRule{
			{Kinds: []string{"Secret"}},
		})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/namespaces/default/configmaps/my-cm", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		data := result["data"].(map[string]any)
		s.Equal("value", data["key"])
	})

	s.Run("masks items in a list response", func() {
		secretList := `{"apiVersion":"v1","kind":"SecretList","items":[{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s1"},"data":{"key":"val"},"type":"Opaque"}]}`
		rt := s.mustNewRT(s.newMockDelegate(secretList), []api.MaskRule{
			{Kinds: []string{"Secret"}},
		})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/secrets", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		items := result["items"].([]any)
		item := items[0].(map[string]any)
		s.Equal("Secret", item["kind"])
		s.Equal("s1", item["metadata"].(map[string]any)["name"])
		s.Equal("[MASK]", item["data"])
		s.Equal("[MASK]", item["type"])
	})

	s.Run("masks items in a Table response", func() {
		table := `{"kind":"Table","rows":[{"object":{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s1"},"data":{"tok":"abc"},"type":"Opaque"}}]}`
		rt := s.mustNewRT(s.newMockDelegate(table), []api.MaskRule{
			{Kinds: []string{"Secret"}},
		})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/secrets", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		rows := result["rows"].([]any)
		rowObj := rows[0].(map[string]any)["object"].(map[string]any)
		s.Equal("Secret", rowObj["kind"])
		s.Equal("[MASK]", rowObj["data"])
		s.Equal("[MASK]", rowObj["type"])
	})
}

func (s *ResponseFilterRoundTripperSuite) TestPathsOnlyRules() {
	s.Run("paths without kind applies to all resources", func() {
		cm := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"my-cm","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"secret-data"}}}`
		rt := s.mustNewRT(s.newMockDelegate(cm), []api.MaskRule{
			{Paths: []string{"metadata.annotations.kubectl.kubernetes.io/last-applied-configuration"}},
		})

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/configmaps/my-cm", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		annotations := result["metadata"].(map[string]any)["annotations"].(map[string]any)
		s.Equal("[MASK]", annotations["kubectl.kubernetes.io/last-applied-configuration"])
	})
}

func (s *ResponseFilterRoundTripperSuite) TestMultiKindRules() {
	s.Run("rule with multiple kinds matches each", func() {
		rules := []api.MaskRule{
			{Kinds: []string{"Secret", "ConfigMap"}, Paths: []string{"data.*"}},
		}

		secret := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s1"},"data":{"key":"val"}}`
		rt := s.mustNewRT(s.newMockDelegate(secret), rules)
		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/secrets/s1", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)
		body, _ := io.ReadAll(resp.Body)
		var secretResult map[string]any
		s.Require().NoError(json.Unmarshal(body, &secretResult))
		s.Equal("[MASK]", secretResult["data"].(map[string]any)["key"])

		cm := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm1"},"data":{"key":"val"}}`
		rt = s.mustNewRT(s.newMockDelegate(cm), rules)
		req = httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/configmaps/cm1", nil)
		resp, err = rt.RoundTrip(req)
		s.Require().NoError(err)
		body, _ = io.ReadAll(resp.Body)
		var cmResult map[string]any
		s.Require().NoError(json.Unmarshal(body, &cmResult))
		s.Equal("[MASK]", cmResult["data"].(map[string]any)["key"])

		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p1"},"data":{"key":"val"}}`
		rt = s.mustNewRT(s.newMockDelegate(pod), rules)
		req = httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/pods/p1", nil)
		resp, err = rt.RoundTrip(req)
		s.Require().NoError(err)
		body, _ = io.ReadAll(resp.Body)
		var podResult map[string]any
		s.Require().NoError(json.Unmarshal(body, &podResult))
		s.Equal("val", podResult["data"].(map[string]any)["key"])
	})
}

func (s *ResponseFilterRoundTripperSuite) TestPathsWithRegex() {
	s.Run("regex applied only to matched field values", func() {
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"my-pod"},"status":{"podIP":"10.244.0.5","phase":"Running"}}`
		rules := []api.MaskRule{
			{Paths: []string{"status.podIP"}, Regex: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`},
		}
		rt := s.mustNewRT(s.newMockDelegate(pod), rules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/pods/my-pod", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		status := result["status"].(map[string]any)
		s.Equal("[MASK]", status["podIP"])
		// phase is not affected because only podIP path is targeted
		s.Equal("Running", status["phase"])
	})

	s.Run("regex with wildcard path masks matching content in all subfields", func() {
		svc := `{"apiVersion":"v1","kind":"Service","metadata":{"name":"svc"},"spec":{"clusterIP":"10.96.0.1","externalIPs":["203.0.113.5"],"type":"ClusterIP"}}`
		rules := []api.MaskRule{
			{Paths: []string{"spec.*"}, Regex: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`},
		}
		rt := s.mustNewRT(s.newMockDelegate(svc), rules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/services/svc", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		spec := result["spec"].(map[string]any)
		s.Equal("[MASK]", spec["clusterIP"])
		// type is a string but doesn't match the IP regex, so unchanged
		s.Equal("ClusterIP", spec["type"])
	})

	s.Run("regex does not affect non-string values", func() {
		obj := `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"cm"},"data":{"count":42,"ip":"10.0.0.1"}}`
		rules := []api.MaskRule{
			{Paths: []string{"data.*"}, Regex: `\b\d+\.\d+\.\d+\.\d+\b`},
		}
		rt := s.mustNewRT(s.newMockDelegate(obj), rules)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/configmaps/cm", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))

		data := result["data"].(map[string]any)
		s.Equal("[MASK]", data["ip"])
		// JSON numbers are float64, not strings — regex doesn't apply
		s.Equal(float64(42), data["count"])
	})

	s.Run("kinds + paths + regex scopes regex to kind and path", func() {
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"},"status":{"podIP":"10.0.0.1"}}`
		svc := `{"apiVersion":"v1","kind":"Service","metadata":{"name":"s"},"spec":{"clusterIP":"10.0.0.2"}}`
		rules := []api.MaskRule{
			{Kinds: []string{"Pod"}, Paths: []string{"status.podIP"}, Regex: `\b\d+\.\d+\.\d+\.\d+\b`},
		}

		// Pod should be masked
		rt := s.mustNewRT(s.newMockDelegate(pod), rules)
		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/pods/p", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)
		body, _ := io.ReadAll(resp.Body)
		var podResult map[string]any
		s.Require().NoError(json.Unmarshal(body, &podResult))
		s.Equal("[MASK]", podResult["status"].(map[string]any)["podIP"])

		// Service should NOT be masked (different kind)
		rt = s.mustNewRT(s.newMockDelegate(svc), rules)
		req = httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/services/s", nil)
		resp, err = rt.RoundTrip(req)
		s.Require().NoError(err)
		body, _ = io.ReadAll(resp.Body)
		var svcResult map[string]any
		s.Require().NoError(json.Unmarshal(body, &svcResult))
		s.Equal("10.0.0.2", svcResult["spec"].(map[string]any)["clusterIP"])
	})
}

func (s *ResponseFilterRoundTripperSuite) TestCustomMaskValue() {
	s.Run("uses custom mask value for field rules", func() {
		secret := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s"},"data":{"key":"val"}}`
		rules := []api.MaskRule{
			{Kinds: []string{"Secret"}, Paths: []string{"data.*"}},
		}
		rt := s.mustNewRTWithMaskValue(s.newMockDelegate(secret), rules, "***REDACTED***")

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/secrets/s", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))
		s.Equal("***REDACTED***", result["data"].(map[string]any)["key"])
	})

	s.Run("uses custom mask value for kind-only rules", func() {
		secret := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s"},"data":{"key":"val"},"type":"Opaque"}`
		rules := []api.MaskRule{
			{Kinds: []string{"Secret"}},
		}
		rt := s.mustNewRTWithMaskValue(s.newMockDelegate(secret), rules, "<HIDDEN>")

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/secrets/s", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))
		s.Equal("<HIDDEN>", result["data"])
		s.Equal("<HIDDEN>", result["type"])
	})

	s.Run("uses custom mask value for regex rules", func() {
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"},"status":{"podIP":"10.0.0.1"}}`
		rules := []api.MaskRule{
			{Regex: `\b\d+\.\d+\.\d+\.\d+\b`},
		}
		rt := s.mustNewRTWithMaskValue(s.newMockDelegate(pod), rules, "X.X.X.X")

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/pods/p", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		s.Contains(string(body), "X.X.X.X")
		s.NotContains(string(body), "10.0.0.1")
	})

	s.Run("defaults to [MASK] when mask value is empty", func() {
		secret := `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"s"},"data":{"key":"val"}}`
		rules := []api.MaskRule{
			{Kinds: []string{"Secret"}, Paths: []string{"data.*"}},
		}
		rt, err := NewResponseFilterRoundTripper(ResponseFilterConfig{
			Delegate:  s.newMockDelegate(secret),
			MaskRules: rules,
			MaskValue: "",
		})
		s.Require().NoError(err)
		s.Require().NotNil(rt)

		req := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/secrets/s", nil)
		resp, err := rt.RoundTrip(req)
		s.Require().NoError(err)

		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		s.Require().NoError(json.Unmarshal(body, &result))
		s.Equal("[MASK]", result["data"].(map[string]any)["key"])
	})
}
