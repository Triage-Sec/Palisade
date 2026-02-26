package evaluators

import (
	"context"
	"testing"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
	"github.com/triage-ai/palisade/services/tool_guard/internal/registry"
)

func TestPrecondition_AllMet(t *testing.T) {
	e := NewPreconditionEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "transfer_funds",
		Trace: []*toolguardv1.TraceEntry{
			{ToolName: "authenticate_user"},
			{ToolName: "validate_account"},
		},
		ToolDef: &registry.ToolDefinition{
			Preconditions: []string{"authenticate_user", "validate_account"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered when all preconditions met")
	}
}

func TestPrecondition_SomeMissing(t *testing.T) {
	e := NewPreconditionEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "transfer_funds",
		Trace: []*toolguardv1.TraceEntry{
			{ToolName: "authenticate_user"},
		},
		ToolDef: &registry.ToolDefinition{
			Preconditions: []string{"authenticate_user", "validate_account"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered when preconditions missing")
	}
	if result.Confidence != 0.95 {
		t.Fatalf("expected 0.95 confidence, got %f", result.Confidence)
	}
}

func TestPrecondition_EmptyTrace(t *testing.T) {
	e := NewPreconditionEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "transfer_funds",
		Trace:    nil,
		ToolDef: &registry.ToolDefinition{
			Preconditions: []string{"authenticate_user"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered when trace is empty but preconditions required")
	}
}

func TestPrecondition_NoPreconditions(t *testing.T) {
	e := NewPreconditionEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "get_user",
		ToolDef:  &registry.ToolDefinition{Preconditions: nil},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered when no preconditions defined")
	}
}

func TestPrecondition_UnregisteredTool(t *testing.T) {
	e := NewPreconditionEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "unknown",
		ToolDef:  nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered for unregistered tool")
	}
}
