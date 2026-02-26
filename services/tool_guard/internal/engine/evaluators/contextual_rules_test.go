package evaluators

import (
	"context"
	"strings"
	"testing"
	"time"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
	"github.com/triage-ai/palisade/services/tool_guard/internal/registry"
)

func TestContextualRules_BlockedWorkflow(t *testing.T) {
	e := NewContextualRulesEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:     "send_email",
		WorkflowType: "public_demo",
		ToolDef: &registry.ToolDefinition{
			ContextualRules: registry.ContextualRules{
				BlockedWorkflows: []string{"public_demo"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered for blocked workflow")
	}
	if !strings.Contains(result.Details, "blocked in workflow") {
		t.Fatalf("expected blocked workflow detail, got: %s", result.Details)
	}
}

func TestContextualRules_AllowedWorkflow(t *testing.T) {
	e := NewContextualRulesEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:     "send_email",
		WorkflowType: "customer_support",
		ToolDef: &registry.ToolDefinition{
			ContextualRules: registry.ContextualRules{
				AllowedWorkflows: []string{"customer_support"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered for allowed workflow")
	}
}

func TestContextualRules_WorkflowNotInAllowed(t *testing.T) {
	e := NewContextualRulesEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:     "send_email",
		WorkflowType: "code_review",
		ToolDef: &registry.ToolDefinition{
			ContextualRules: registry.ContextualRules{
				AllowedWorkflows: []string{"customer_support"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered when workflow not in allowed list")
	}
}

func TestContextualRules_RateLimitExceeded(t *testing.T) {
	e := NewContextualRulesEvaluator()
	nowMs := time.Now().UnixMilli()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "send_email",
		Trace: []*toolguardv1.TraceEntry{
			{ToolName: "send_email", TimestampMs: nowMs - 1000},
			{ToolName: "send_email", TimestampMs: nowMs - 2000},
			{ToolName: "send_email", TimestampMs: nowMs - 3000},
			{ToolName: "send_email", TimestampMs: nowMs - 4000},
			{ToolName: "send_email", TimestampMs: nowMs - 5000},
		},
		ToolDef: &registry.ToolDefinition{
			ToolName: "send_email",
			ContextualRules: registry.ContextualRules{
				RateLimit: &registry.RateLimit{MaxCalls: 5, WindowSeconds: 60},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered for rate limit exceeded")
	}
	if !strings.Contains(result.Details, "rate limit exceeded") {
		t.Fatalf("expected rate limit detail, got: %s", result.Details)
	}
}

func TestContextualRules_RateLimitNotExceeded(t *testing.T) {
	e := NewContextualRulesEvaluator()
	nowMs := time.Now().UnixMilli()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "send_email",
		Trace: []*toolguardv1.TraceEntry{
			{ToolName: "send_email", TimestampMs: nowMs - 1000},
			{ToolName: "send_email", TimestampMs: nowMs - 2000},
		},
		ToolDef: &registry.ToolDefinition{
			ToolName: "send_email",
			ContextualRules: registry.ContextualRules{
				RateLimit: &registry.RateLimit{MaxCalls: 5, WindowSeconds: 60},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered when under rate limit")
	}
}

func TestContextualRules_RateLimitExpiredEntries(t *testing.T) {
	e := NewContextualRulesEvaluator()
	nowMs := time.Now().UnixMilli()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "send_email",
		Trace: []*toolguardv1.TraceEntry{
			{ToolName: "send_email", TimestampMs: nowMs - 120_000}, // 2 min ago, outside 60s window
			{ToolName: "send_email", TimestampMs: nowMs - 130_000},
			{ToolName: "send_email", TimestampMs: nowMs - 140_000},
			{ToolName: "send_email", TimestampMs: nowMs - 150_000},
			{ToolName: "send_email", TimestampMs: nowMs - 160_000},
		},
		ToolDef: &registry.ToolDefinition{
			ToolName: "send_email",
			ContextualRules: registry.ContextualRules{
				RateLimit: &registry.RateLimit{MaxCalls: 5, WindowSeconds: 60},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered when all entries are outside the window")
	}
}

func TestContextualRules_UnregisteredTool(t *testing.T) {
	e := NewContextualRulesEvaluator()
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

func TestContextualRules_ZeroTimestampExcluded(t *testing.T) {
	e := NewContextualRulesEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName: "send_email",
		Trace: []*toolguardv1.TraceEntry{
			{ToolName: "send_email", TimestampMs: 0},
			{ToolName: "send_email", TimestampMs: 0},
			{ToolName: "send_email", TimestampMs: 0},
			{ToolName: "send_email", TimestampMs: 0},
			{ToolName: "send_email", TimestampMs: 0},
		},
		ToolDef: &registry.ToolDefinition{
			ToolName: "send_email",
			ContextualRules: registry.ContextualRules{
				RateLimit: &registry.RateLimit{MaxCalls: 3, WindowSeconds: 60},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered when timestamps are all zero")
	}
}
