package api

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type MaskRuleSuite struct {
	suite.Suite
}

func (s *MaskRuleSuite) TestTableIncompatibleKinds() {
	s.Run("no rules", func() {
		kinds, allKinds := TableIncompatibleKinds(nil)
		s.Empty(kinds)
		s.False(allKinds)
	})
	s.Run("kind-only rule is table compatible", func() {
		kinds, allKinds := TableIncompatibleKinds([]MaskRule{{Kinds: []string{"Secret"}}})
		s.Empty(kinds)
		s.False(allKinds)
	})
	s.Run("regex-only rule is table compatible", func() {
		kinds, allKinds := TableIncompatibleKinds([]MaskRule{{Regex: `\d+`}})
		s.Empty(kinds)
		s.False(allKinds)
	})
	s.Run("metadata paths are table compatible", func() {
		kinds, allKinds := TableIncompatibleKinds([]MaskRule{
			{Paths: []string{"metadata.annotations.kubectl.kubernetes.io/last-applied-configuration"}},
		})
		s.Empty(kinds)
		s.False(allKinds)
	})
	s.Run("non-metadata paths are table incompatible for the rule kinds", func() {
		kinds, allKinds := TableIncompatibleKinds([]MaskRule{
			{Kinds: []string{"Service"}, Paths: []string{"status.loadBalancer.ingress.ip"}},
			{Kinds: []string{"Secret"}, Paths: []string{"data.*"}},
		})
		s.Equal([]string{"Secret", "Service"}, kinds)
		s.False(allKinds)
	})
	s.Run("mixed metadata and non-metadata paths are table incompatible", func() {
		kinds, allKinds := TableIncompatibleKinds([]MaskRule{
			{Kinds: []string{"Pod"}, Paths: []string{"metadata.labels.app", "spec.containers.env.value"}},
		})
		s.Equal([]string{"Pod"}, kinds)
		s.False(allKinds)
	})
	s.Run("non-metadata paths without kinds affect all kinds", func() {
		kinds, allKinds := TableIncompatibleKinds([]MaskRule{{Paths: []string{"data.*"}}})
		s.Empty(kinds)
		s.True(allKinds)
	})
	s.Run("wildcard kind affects all kinds", func() {
		_, allKinds := TableIncompatibleKinds([]MaskRule{{Kinds: []string{"*"}, Paths: []string{"data.*"}}})
		s.True(allKinds)
	})
	s.Run("duplicate kinds are reported once", func() {
		kinds, _ := TableIncompatibleKinds([]MaskRule{
			{Kinds: []string{"Service"}, Paths: []string{"spec.clusterIP"}},
			{Kinds: []string{"Service"}, Paths: []string{"status.loadBalancer.ingress.ip"}},
		})
		s.Equal([]string{"Service"}, kinds)
	})
}

func (s *MaskRuleSuite) TestIsTableOutputAllowed() {
	rules := []MaskRule{
		{Kinds: []string{"Service"}, Paths: []string{"status.loadBalancer.ingress.ip"}},
		{Paths: []string{"metadata.annotations.kubectl.kubernetes.io/last-applied-configuration"}},
	}
	s.Run("false for an incompatible kind", func() {
		s.False(IsTableOutputAllowed(rules, "Service"))
	})
	s.Run("true for an unaffected kind", func() {
		s.True(IsTableOutputAllowed(rules, "Pod"))
	})
	s.Run("false for every kind when a rule is not kind-scoped", func() {
		s.False(IsTableOutputAllowed([]MaskRule{{Paths: []string{"data.*"}}}, "Pod"))
	})
}

func TestMaskRule(t *testing.T) {
	suite.Run(t, new(MaskRuleSuite))
}
