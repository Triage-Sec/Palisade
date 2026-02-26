package evaluators

import (
	"context"
	"testing"

	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
	"github.com/triage-ai/palisade/services/tool_guard/internal/registry"
)

func TestRiskTier_UnregisteredTool(t *testing.T) {
	e := NewRiskTierEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "unknown_tool",
		ToolDef:  nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered for unregistered tool")
	}
	if result.Confidence != 0.5 {
		t.Fatalf("expected 0.5 confidence, got %f", result.Confidence)
	}
}

func TestRiskTier_DestructiveUnconfirmed(t *testing.T) {
	e := NewRiskTierEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "delete_account",
		UserConfirmed: false,
		ToolDef: &registry.ToolDefinition{
			RiskTier:        "destructive",
			RequiresConfirm: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered for unconfirmed destructive tool")
	}
	if result.Confidence != 0.95 {
		t.Fatalf("expected 0.95 confidence, got %f", result.Confidence)
	}
}

func TestRiskTier_DestructiveConfirmed(t *testing.T) {
	e := NewRiskTierEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "delete_account",
		UserConfirmed: true,
		ToolDef: &registry.ToolDefinition{
			RiskTier:        "destructive",
			RequiresConfirm: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered for confirmed destructive tool")
	}
}

func TestRiskTier_ReadTool(t *testing.T) {
	e := NewRiskTierEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "get_user",
		ToolDef:  &registry.ToolDefinition{RiskTier: "read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered for read tool")
	}
}

func TestRiskTier_DestructiveNoConfirmRequired(t *testing.T) {
	e := NewRiskTierEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "purge_cache",
		UserConfirmed: false,
		ToolDef: &registry.ToolDefinition{
			RiskTier:        "destructive",
			RequiresConfirm: false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered: destructive but no confirmation required")
	}
}
