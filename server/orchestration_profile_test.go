package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestSpawnTaskInheritsParentAgentProfile(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	parent, err := m.CreateTaskWithOptions("vulnerability parent", "audit fixture", db.TaskCreateOptions{
		AgentProfileKey: db.VulnerabilityAgentProfileKey,
		AccessMode:      db.AccessModeUnauthenticated,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, callErr := s.toolSpawnTask().Call(ctx, json.RawMessage(`{
        "description":"inherited child",
        "goal":"verify one candidate",
        "parent_ref":"`+parent.ID+`"
    }`), nil)
	if callErr != nil {
		t.Fatal(callErr)
	}

	var child *Task
	for _, task := range m.List() {
		if task.ID != parent.ID && task.ParentRef == parent.ID {
			child = task
			break
		}
	}
	if child == nil {
		t.Fatal("spawn_task did not create a linked child")
	}
	if child.AgentProfileKey != db.VulnerabilityAgentProfileKey || child.AccessMode != db.AccessModeUnauthenticated || child.CoordinationMode != db.CoordinationModeOrchestrated || !child.CoverageEnabled {
		t.Fatalf("child did not inherit profile defaults: %+v", child)
	}

	s.engine.StopTask(child.ID)
	s.engine.StopTask(parent.ID)
	_, _ = m.DeleteTask(child.ID, DeleteTaskOptions{})
	_, _ = m.DeleteTask(parent.ID, DeleteTaskOptions{})
}
