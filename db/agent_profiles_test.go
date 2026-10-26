package db

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestAgentProfileValueHelpers(t *testing.T) {
	if got := NormalizeAgentProfileKey("  "); got != DefaultAgentProfileKey {
		t.Fatalf("blank profile = %q, want %q", got, DefaultAgentProfileKey)
	}
	if got := NormalizeAgentProfileKey(" vuln_research "); got != VulnerabilityAgentProfileKey {
		t.Fatalf("trimmed profile = %q", got)
	}
	if !(AgentProfileRoleKeys{Goals: "g", Planner: "p", Worker: "w", Main: "m"}).Complete() {
		t.Fatal("complete role set reported incomplete")
	}
	if (AgentProfileRoleKeys{Goals: "g", Planner: "p", Worker: "w"}).Complete() {
		t.Fatal("role set without main reported complete")
	}
}

func TestBuiltinAgentProfilesAndTaskDefaults(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	pentest, err := d.AgentProfileByKey("")
	if err != nil {
		t.Fatal(err)
	}
	if pentest.Key != DefaultAgentProfileKey || !pentest.DefaultCoverageEnabled {
		t.Fatalf("pentest profile = %+v", pentest)
	}
	if pentest.Roles != (AgentProfileRoleKeys{Goals: "goals", Planner: "planner", Worker: "worker", Main: "mainagent"}) {
		t.Fatalf("pentest roles = %+v", pentest.Roles)
	}

	vuln, err := d.AgentProfileByKey(VulnerabilityAgentProfileKey)
	if err != nil {
		t.Fatal(err)
	}
	if vuln.DefaultCoverageEnabled {
		t.Fatalf("vulnerability profile should default coverage off: %+v", vuln)
	}
	if vuln.Roles != (AgentProfileRoleKeys{Goals: "vuln_goals", Planner: "vuln_planner", Worker: "vuln_worker", Main: "vuln_mainagent"}) {
		t.Fatalf("vulnerability roles = %+v", vuln.Roles)
	}

	legacy, err := d.CreateTask("profile default", "legacy behavior", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(legacy.ID) })
	if legacy.AgentProfileKey != DefaultAgentProfileKey || !legacy.CoverageEnabled {
		t.Fatalf("legacy task profile/default = %+v", legacy)
	}

	research, err := d.CreateTaskWithOptions("profile research", "audit fixture", TaskCreateOptions{
		AgentProfileKey: VulnerabilityAgentProfileKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(research.ID) })
	if research.AgentProfileKey != VulnerabilityAgentProfileKey || research.AccessMode != AccessModeSourceAssisted || research.CoordinationMode != CoordinationModeOrchestrated || research.CoverageEnabled {
		t.Fatalf("research task profile/default = %+v", research)
	}
	uagent, err := d.CreateTaskWithOptions("u agent research", "pre-auth fixture", TaskCreateOptions{
		AgentProfileKey: VulnerabilityAgentProfileKey,
		AccessMode:      AccessModeUnauthenticated,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(uagent.ID) })
	if uagent.AccessMode != AccessModeUnauthenticated || !uagent.CoverageEnabled {
		t.Fatalf("u agent defaults = %+v", uagent)
	}

	if _, err := d.CreateTaskWithOptions("bad profile", "must reject", TaskCreateOptions{AgentProfileKey: "missing"}); !errors.Is(err, ErrAgentProfileNotFound) {
		t.Fatalf("invalid profile err = %v, want ErrAgentProfileNotFound", err)
	}

	template, err := d.CreateTaskTemplate(TaskTemplateInput{
		Name: fmt.Sprintf("vuln-profile-%d", time.Now().UnixNano()), Description: "source audit", Goal: "produce evidence",
		AgentProfileKey: VulnerabilityAgentProfileKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.DeleteTaskTemplate(template.ID) })
	if template.AgentProfileKey != VulnerabilityAgentProfileKey || template.AccessMode != AccessModeSourceAssisted {
		t.Fatalf("template profile = %q", template.AgentProfileKey)
	}
}
