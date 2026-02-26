package evaluators

import (
	"context"
	"strings"
	"testing"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
	"github.com/triage-ai/palisade/services/tool_guard/internal/registry"
)

func TestArgValidation_SchemaValid(t *testing.T) {
	e := NewArgumentValidationEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "send_email",
		ArgumentsJSON: `{"to":"user@example.com","subject":"Hello"}`,
		ToolDef: &registry.ToolDefinition{
			ArgumentSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"to":      map[string]any{"type": "string"},
					"subject": map[string]any{"type": "string"},
				},
				"required": []any{"to", "subject"},
			},
			ArgumentPolicy: registry.ArgumentPolicy{
				ScanForPII:       false,
				ScanForInjection: false,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatalf("expected not triggered, got: %s", result.Details)
	}
}

func TestArgValidation_SchemaInvalid(t *testing.T) {
	e := NewArgumentValidationEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "send_email",
		ArgumentsJSON: `{"subject":"Hello"}`,
		ToolDef: &registry.ToolDefinition{
			ArgumentSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"to":      map[string]any{"type": "string"},
					"subject": map[string]any{"type": "string"},
				},
				"required": []any{"to"},
			},
			ArgumentPolicy: registry.ArgumentPolicy{
				ScanForPII:       false,
				ScanForInjection: false,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered for missing required field")
	}
	if !strings.Contains(result.Details, "schema validation failed") {
		t.Fatalf("expected schema error, got: %s", result.Details)
	}
}

func TestArgValidation_PIIDetected(t *testing.T) {
	e := NewArgumentValidationEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "send_email",
		ArgumentsJSON: `{"body":"My SSN is 123-45-6789"}`,
		ToolDef: &registry.ToolDefinition{
			ArgumentPolicy: registry.ArgumentPolicy{
				ScanForPII:       true,
				ScanForInjection: false,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered for PII in arguments")
	}
	if !strings.Contains(result.Details, "PII") {
		t.Fatalf("expected PII detail, got: %s", result.Details)
	}
}

func TestArgValidation_InjectionDetected(t *testing.T) {
	e := NewArgumentValidationEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "query_db",
		ArgumentsJSON: `{"query":"SELECT * FROM users WHERE id=1; DROP TABLE users"}`,
		ToolDef: &registry.ToolDefinition{
			ArgumentPolicy: registry.ArgumentPolicy{
				ScanForPII:       false,
				ScanForInjection: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered for injection in arguments")
	}
	if !strings.Contains(result.Details, "injection") {
		t.Fatalf("expected injection detail, got: %s", result.Details)
	}
}

func TestArgValidation_UnregisteredTool_InjectionScan(t *testing.T) {
	e := NewArgumentValidationEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "unknown_tool",
		ArgumentsJSON: `{"cmd":"; rm -rf /"}`,
		ToolDef:       nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered for injection in unregistered tool args")
	}
}

func TestArgValidation_CleanArgs(t *testing.T) {
	e := NewArgumentValidationEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "get_weather",
		ArgumentsJSON: `{"city":"San Francisco"}`,
		ToolDef: &registry.ToolDefinition{
			ArgumentPolicy: registry.ArgumentPolicy{
				ScanForPII:       true,
				ScanForInjection: true,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatalf("expected not triggered for clean args, got: %s", result.Details)
	}
}

func TestArgValidation_TraceBinding_Match(t *testing.T) {
	e := NewArgumentValidationEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "transfer_funds",
		ArgumentsJSON: `{"amount":100,"account_id":"acc-123"}`,
		Trace: []*toolguardv1.TraceEntry{
			{
				ToolName:   "get_quote",
				ResultJson: `{"amount":100}`,
			},
			{
				ToolName:   "lookup_account",
				ResultJson: `{"id":"acc-123"}`,
			},
		},
		ToolDef: &registry.ToolDefinition{
			ArgumentPolicy: registry.ArgumentPolicy{
				ScanForPII:       false,
				ScanForInjection: false,
				TraceBinding: map[string]string{
					"amount":     "get_quote.result.amount",
					"account_id": "lookup_account.result.id",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatalf("expected not triggered when trace binding matches, got: %s", result.Details)
	}
}

func TestArgValidation_TraceBinding_Mismatch(t *testing.T) {
	e := NewArgumentValidationEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "transfer_funds",
		ArgumentsJSON: `{"amount":999,"account_id":"acc-123"}`,
		Trace: []*toolguardv1.TraceEntry{
			{
				ToolName:   "get_quote",
				ResultJson: `{"amount":100}`,
			},
			{
				ToolName:   "lookup_account",
				ResultJson: `{"id":"acc-123"}`,
			},
		},
		ToolDef: &registry.ToolDefinition{
			ArgumentPolicy: registry.ArgumentPolicy{
				ScanForPII:       false,
				ScanForInjection: false,
				TraceBinding: map[string]string{
					"amount":     "get_quote.result.amount",
					"account_id": "lookup_account.result.id",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered when trace binding mismatches")
	}
	if !strings.Contains(result.Details, "trace binding mismatch") {
		t.Fatalf("expected trace binding error, got: %s", result.Details)
	}
}
