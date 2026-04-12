package executor

import (
	"testing"
)

func TestNewFlowEngine(t *testing.T) {
	fe := NewFlowEngine()
	if fe == nil {
		t.Fatal("NewFlowEngine() returned nil")
	}
}

func TestFlowEngine_Parse_Empty(t *testing.T) {
	fe := NewFlowEngine()
	steps := fe.Parse("")
	if len(steps) != 0 {
		t.Errorf("Parse(\"\") = %v, want empty", steps)
	}
}

func TestFlowEngine_Parse_SingleHTTP(t *testing.T) {
	fe := NewFlowEngine()
	steps := fe.Parse("http(1)")

	if len(steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(steps))
	}
	if steps[0].Protocol != "http" {
		t.Errorf("Protocol = %q, want %q", steps[0].Protocol, "http")
	}
	if steps[0].Index != 1 {
		t.Errorf("Index = %d, want 1", steps[0].Index)
	}
	if steps[0].Operator != "" {
		t.Errorf("Operator = %q, want empty", steps[0].Operator)
	}
}

func TestFlowEngine_Parse_HTTPAndAnd(t *testing.T) {
	fe := NewFlowEngine()
	steps := fe.Parse("http(1) && http(2)")

	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}

	if steps[0].Protocol != "http" || steps[0].Index != 1 || steps[0].Operator != "" {
		t.Errorf("step[0] = %+v, want {http, 1, \"\"}", steps[0])
	}

	if steps[1].Protocol != "http" || steps[1].Index != 2 || steps[1].Operator != "&&" {
		t.Errorf("step[1] = %+v, want {http, 2, \"&&\"}", steps[1])
	}
}

func TestFlowEngine_Parse_MultiProtocol(t *testing.T) {
	fe := NewFlowEngine()
	steps := fe.Parse("http(1) && dns(1)")

	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}

	if steps[0].Protocol != "http" {
		t.Errorf("step[0].Protocol = %q, want \"http\"", steps[0].Protocol)
	}
	if steps[1].Protocol != "dns" {
		t.Errorf("step[1].Protocol = %q, want \"dns\"", steps[1].Protocol)
	}
	if steps[1].Operator != "&&" {
		t.Errorf("step[1].Operator = %q, want \"&&\"", steps[1].Operator)
	}
}

func TestFlowEngine_Parse_OrOperator(t *testing.T) {
	fe := NewFlowEngine()
	steps := fe.Parse("http(1) || http(2)")

	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}

	if steps[1].Operator != "||" {
		t.Errorf("step[1].Operator = %q, want \"||\"", steps[1].Operator)
	}
}

func TestFlowEngine_Parse_NoIndex(t *testing.T) {
	fe := NewFlowEngine()
	steps := fe.Parse("http()")

	if len(steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(steps))
	}
	if steps[0].Index != 0 {
		t.Errorf("Index = %d, want 0 (execute all)", steps[0].Index)
	}
}

func TestFlowEngine_Parse_ThreeSteps(t *testing.T) {
	fe := NewFlowEngine()
	steps := fe.Parse("http(1) && http(2) && dns(1)")

	if len(steps) != 3 {
		t.Fatalf("expected 3 steps, got %d", len(steps))
	}

	if steps[2].Protocol != "dns" || steps[2].Operator != "&&" {
		t.Errorf("step[2] = %+v, want {dns, 1, \"&&\"}", steps[2])
	}
}

func TestFlowEngine_Parse_AllProtocols(t *testing.T) {
	fe := NewFlowEngine()
	flow := "http(1) && dns(1) && ssl(1) && tcp(1) && network(1) && headless(1) && websocket(1) && whois(1)"
	steps := fe.Parse(flow)

	if len(steps) != 8 {
		t.Fatalf("expected 8 steps, got %d", len(steps))
	}

	protocols := []string{"http", "dns", "ssl", "tcp", "network", "headless", "websocket", "whois"}
	for i, p := range protocols {
		if steps[i].Protocol != p {
			t.Errorf("steps[%d].Protocol = %q, want %q", i, steps[i].Protocol, p)
		}
	}
}

func TestFlowEngine_ShouldContinue_NoOperator(t *testing.T) {
	fe := NewFlowEngine()
	if !fe.ShouldContinue("", true) {
		t.Error("ShouldContinue(\"\", true) should return true")
	}
	if !fe.ShouldContinue("", false) {
		t.Error("ShouldContinue(\"\", false) should return true")
	}
}

func TestFlowEngine_ShouldContinue_AND(t *testing.T) {
	fe := NewFlowEngine()
	tests := []struct {
		previousMatched bool
		want            bool
	}{
		{true, true},
		{false, false},
	}
	for _, tt := range tests {
		got := fe.ShouldContinue("&&", tt.previousMatched)
		if got != tt.want {
			t.Errorf("ShouldContinue(\"&&\", %v) = %v, want %v", tt.previousMatched, got, tt.want)
		}
	}
}

func TestFlowEngine_ShouldContinue_OR(t *testing.T) {
	fe := NewFlowEngine()
	tests := []struct {
		previousMatched bool
		want            bool
	}{
		{true, false},
		{false, true},
	}
	for _, tt := range tests {
		got := fe.ShouldContinue("||", tt.previousMatched)
		if got != tt.want {
			t.Errorf("ShouldContinue(\"||\", %v) = %v, want %v", tt.previousMatched, got, tt.want)
		}
	}
}

func TestFlowEngine_Parse_InvalidFlow(t *testing.T) {
	fe := NewFlowEngine()
	steps := fe.Parse("invalid flow string")
	if len(steps) != 0 {
		t.Errorf("Parse(\"invalid\") = %v, want empty", steps)
	}
}
