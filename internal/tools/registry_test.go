package tools

import (
	"context"
	"testing"
	"time"
)

// stubTool implements Tool for testing.
type stubTool struct {
	name      string
	available bool
}

func (s *stubTool) Name() string      { return s.name }
func (s *stubTool) Version() string   { return "1.0.0" }
func (s *stubTool) IsAvailable() bool { return s.available }
func (s *stubTool) HealthCheck() error { return nil }
func (s *stubTool) Execute(_ context.Context, _ *ToolRequest) (*ToolResult, error) {
	return NewToolResult(s.name), nil
}

func TestRegistryAvailable(t *testing.T) {
	r := NewRegistry([]Tool{
		&stubTool{name: "sqlmap", available: true},
		&stubTool{name: "missing", available: false},
		&stubTool{name: "dalfox", available: true},
	})

	avail := r.Available()
	if len(avail) != 2 {
		t.Fatalf("expected 2 available tools, got %d", len(avail))
	}
}

func TestRegistryByName(t *testing.T) {
	r := NewRegistry([]Tool{
		&stubTool{name: "sqlmap", available: true},
	})

	if tool := r.ByName("sqlmap"); tool == nil {
		t.Error("expected to find sqlmap")
	}
	if tool := r.ByName("nope"); tool != nil {
		t.Error("expected nil for unknown tool")
	}
}

func TestRegistryForClass(t *testing.T) {
	r := NewRegistry([]Tool{
		&stubTool{name: "sqlmap", available: true},
		&stubTool{name: "ghauri", available: true},
		&stubTool{name: "dalfox", available: false},
	})

	sqliTools := r.ForClass("sqli")
	if len(sqliTools) != 2 {
		t.Fatalf("expected 2 sqli tools, got %d", len(sqliTools))
	}

	xssTools := r.ForClass("xss")
	if len(xssTools) != 0 {
		t.Fatalf("expected 0 xss tools (dalfox unavailable), got %d", len(xssTools))
	}
}

// Ensure stubTool compiles as Tool — catches interface drift.
var _ Tool = (*stubTool)(nil)

// Silence unused import if time is not otherwise needed.
var _ = time.Second
