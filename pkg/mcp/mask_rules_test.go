package mcp

import (
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/suite"
)

type MaskRulesSuite struct {
	BaseMcpSuite
}

const ipv4MaskRegex = `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:/[0-9]{1,2})?\b`

func (s *MaskRulesSuite) TestKindScopedRegexMasksTableCells() {
	s.Cfg.ListOutput = "table"
	s.Require().NoError(toml.Unmarshal([]byte(`
		[[mask_rules]]
		kinds = ["Service"]
		regex = '`+ipv4MaskRegex+`'
	`), s.Cfg), "Expected to parse mask_rules config")
	s.InitMcpClient()

	s.Run("resources_list(kind=Service) masks the cluster IP cell", func() {
		serviceList, err := s.CallTool("resources_list", map[string]interface{}{"apiVersion": "v1", "kind": "Service"})
		s.Require().Nilf(err, "call tool failed %v", err)
		s.Require().Falsef(serviceList.IsError, "call tool failed")
		out := serviceList.Content[0].(*mcp.TextContent).Text
		s.Regexpf(`CLUSTER-IP\s`, out, "Expected table output, got:\n%s", out)
		s.Regexpf(`kubernetes\s+ClusterIP\s+\[MASK\]`, out, "Expected a masked cluster IP, got:\n%s", out)
	})

	s.Run("pods_list is not affected by a Service-scoped rule", func() {
		podList, err := s.CallTool("pods_list", map[string]interface{}{})
		s.Require().Nilf(err, "call tool failed %v", err)
		s.Require().Falsef(podList.IsError, "call tool failed")
		s.NotContains(podList.Content[0].(*mcp.TextContent).Text, "[MASK]")
	})
}

func (s *MaskRulesSuite) TestNonMetadataPathRuleFallsBackToYaml() {
	s.Cfg.ListOutput = "table"
	s.Require().NoError(toml.Unmarshal([]byte(`
		[[mask_rules]]
		kinds = ["Service"]
		paths = ["spec.clusterIP"]
	`), s.Cfg), "Expected to parse mask_rules config")
	s.InitMcpClient()

	s.Run("resources_list(kind=Service) returns yaml with the path masked", func() {
		serviceList, err := s.CallTool("resources_list", map[string]interface{}{"apiVersion": "v1", "kind": "Service"})
		s.Require().Nilf(err, "call tool failed %v", err)
		s.Require().Falsef(serviceList.IsError, "call tool failed")
		out := serviceList.Content[0].(*mcp.TextContent).Text
		s.Containsf(out, "clusterIP: '[MASK]'", "Expected yaml output with a masked clusterIP, got:\n%s", out)
	})

	s.Run("resources_list(kind=ConfigMap) still uses table output", func() {
		configMapList, err := s.CallTool("resources_list", map[string]interface{}{"apiVersion": "v1", "kind": "ConfigMap"})
		s.Require().Nilf(err, "call tool failed %v", err)
		s.Require().Falsef(configMapList.IsError, "call tool failed")
		s.Contains(configMapList.Content[0].(*mcp.TextContent).Text, "APIVERSION")
	})
}

func TestMaskRules(t *testing.T) {
	suite.Run(t, new(MaskRulesSuite))
}
