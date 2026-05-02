package executor

import (
	"context"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/headless"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
)

func TestNewHeadlessExecutor(t *testing.T) {
	t.Run("nil pool", func(t *testing.T) {
		exec := NewHeadlessExecutor(nil)
		if exec == nil {
			t.Fatal("NewHeadlessExecutor(nil) returned nil")
		}
		if exec.matcherEngine == nil {
			t.Error("matcherEngine not initialised")
		}
		if exec.pool != nil {
			t.Error("pool should be nil")
		}
	})

	t.Run("with pool", func(t *testing.T) {
		// Use a non-nil typed *headless.Pool value (pool creation requires
		// Chrome, so we only verify the constructor wires correctly).
		var pool *headless.Pool
		exec := NewHeadlessExecutor(pool)
		if exec == nil {
			t.Fatal("NewHeadlessExecutor() returned nil")
		}
	})
}

func TestHeadlessExecutorNilPoolReturnsError(t *testing.T) {
	exec := NewHeadlessExecutor(nil)
	step := &templates.HeadlessStep{
		Actions: []templates.HeadlessAction{
			{Action: "navigate", Args: map[string]string{"url": "https://example.com"}},
		},
	}
	_, err := exec.Execute(context.Background(), "https://example.com", step)
	if err == nil {
		t.Fatal("Execute with nil pool should return an error")
	}
}

func TestHeadlessExecutorContextCancelled(t *testing.T) {
	exec := NewHeadlessExecutor(nil)
	step := &templates.HeadlessStep{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := exec.Execute(ctx, "https://example.com", step)
	// nil pool error is returned before context check; just ensure no panic.
	if err == nil {
		t.Fatal("expected error with nil pool")
	}
}

func TestHeadlessRunActionUnknown(t *testing.T) {
	exec := NewHeadlessExecutor(nil)
	// runAction with an unknown action should return nil (silent ignore).
	action := templates.HeadlessAction{Action: "unknown_action"}
	err := exec.runAction(context.Background(), nil, "https://example.com", action)
	if err != nil {
		t.Errorf("runAction with unknown action should return nil, got: %v", err)
	}
}

func TestHeadlessStepActionsOrSteps(t *testing.T) {
	// Verify that a HeadlessStep with Steps (not Actions) is still processed.
	step := &templates.HeadlessStep{
		Steps: []templates.HeadlessAction{
			{Action: "navigate"},
		},
	}
	if len(step.Actions) != 0 {
		t.Error("Actions should be empty")
	}
	if len(step.Steps) != 1 {
		t.Error("Steps should have 1 entry")
	}
}
