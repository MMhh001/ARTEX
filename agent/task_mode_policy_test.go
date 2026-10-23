package agent

import (
	"strings"
	"testing"
)

func TestUnauthenticatedResearchPolicyContainsHardBoundaries(t *testing.T) {
	for _, required := range []string{"不得读取", "空 Cookie Jar", "匿名起点", "Authorization", "blocked/rejected"} {
		if !strings.Contains(UnauthenticatedResearchPolicy, required) {
			t.Fatalf("policy missing %q", required)
		}
	}
	if got := appendTaskPolicy("base", UnauthenticatedResearchPolicy); !strings.HasPrefix(got, "base") || !strings.Contains(got, "U Agent") {
		t.Fatalf("policy was not appended: %q", got)
	}
}
