package server

import (
	"testing"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/registry"
)

// These tests validate that tool_guard's rule-based evaluators catch the same
// error classes detected by qualifire/mcp-tool-use-quality-ranger-0.6b:
//
//   VALID_CALL       — tool name, params, and values are all correct
//   TOOL_ERROR       — tool name doesn't exist or doesn't match intent
//   PARAM_NAME_ERROR — correct tool, but param names are wrong/missing/extra
//   PARAM_VALUE_ERROR — tool and params correct, but values are wrong
//
// See: https://huggingface.co/qualifire/mcp-tool-use-quality-ranger-0.6b

func mcpToolRegistry() registry.ToolRegistry {
	return &stubRegistry{
		tools: map[string]*registry.ToolDefinition{
			"order_food": {
				ToolName: "order_food",
				RiskTier: "write",
				ArgumentSchema: map[string]any{
					"type": "object",
					"required": []any{"item_name", "quantity"},
					"properties": map[string]any{
						"item_name": map[string]any{"type": "string"},
						"quantity":  map[string]any{"type": "integer", "minimum": float64(1)},
					},
					"additionalProperties": false,
				},
				ArgumentPolicy: registry.ArgumentPolicy{
					ScanForPII:       false,
					ScanForInjection: true,
				},
			},
			"get_weather": {
				ToolName: "get_weather",
				RiskTier: "read",
				ArgumentSchema: map[string]any{
					"type": "object",
					"required": []any{"location"},
					"properties": map[string]any{
						"location": map[string]any{"type": "string"},
						"unit":     map[string]any{"type": "string", "enum": []any{"celsius", "fahrenheit"}},
					},
					"additionalProperties": false,
				},
				ArgumentPolicy: registry.ArgumentPolicy{
					ScanForPII:       false,
					ScanForInjection: false,
				},
			},
			"send_email": {
				ToolName: "send_email",
				RiskTier: "write",
				ArgumentSchema: map[string]any{
					"type": "object",
					"required": []any{"to", "subject", "body"},
					"properties": map[string]any{
						"to":      map[string]any{"type": "string"},
						"subject": map[string]any{"type": "string"},
						"body":    map[string]any{"type": "string"},
					},
					"additionalProperties": false,
				},
				ArgumentPolicy: registry.ArgumentPolicy{
					ScanForPII:       true,
					ScanForInjection: true,
				},
			},
			"transfer_funds": {
				ToolName: "transfer_funds",
				RiskTier: "destructive",
				RequiresConfirm: true,
				Preconditions: []string{"authenticate_user", "get_account"},
				ArgumentSchema: map[string]any{
					"type": "object",
					"required": []any{"from_account", "to_account", "amount", "currency"},
					"properties": map[string]any{
						"from_account": map[string]any{"type": "string"},
						"to_account":   map[string]any{"type": "string"},
						"amount":       map[string]any{"type": "number", "minimum": float64(0.01)},
						"currency":     map[string]any{"type": "string", "enum": []any{"USD", "EUR", "GBP"}},
					},
					"additionalProperties": false,
				},
				ArgumentPolicy: registry.ArgumentPolicy{
					ScanForPII:       false,
					ScanForInjection: true,
					TraceBinding: map[string]string{
						"from_account": "get_account.result.account_id",
					},
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// VALID_CALL — tool name, params, and values are all correct → SAFE
// ---------------------------------------------------------------------------

func TestMCP_ValidCall_OrderFood(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "order_food",
		ArgumentsJson: `{"item_name":"Margherita Pizza","quantity":2}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE {
		t.Fatalf("VALID_CALL: expected SAFE, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_ValidCall_GetWeather(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "get_weather",
		ArgumentsJson: `{"location":"San Francisco","unit":"celsius"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE {
		t.Fatalf("VALID_CALL: expected SAFE, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_ValidCall_TransferFundsWithTrace(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "transfer_funds",
		ArgumentsJson: `{"from_account":"acc-123","to_account":"acc-456","amount":50.00,"currency":"USD"}`,
		UserConfirmed: true,
		Trace: []*toolguardv1.TraceEntry{
			{ToolName: "authenticate_user", ResultJson: `{"ok":true}`},
			{ToolName: "get_account", ResultJson: `{"account_id":"acc-123"}`},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE {
		t.Fatalf("VALID_CALL: expected SAFE, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

// ---------------------------------------------------------------------------
// TOOL_ERROR — tool name doesn't exist → unregistered tool path
// ---------------------------------------------------------------------------

func TestMCP_ToolError_NonexistentTool(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// "order_pizza" doesn't exist — user meant "order_food"
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "order_pizza",
		ArgumentsJson: `{"item_name":"Margherita Pizza","quantity":2}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Unregistered tool fires risk_tier at 0.5 (below threshold) → SAFE
	// but the evaluator DOES flag it — verify the evaluation contains the signal
	found := false
	for _, eval := range resp.Evaluations {
		if eval.Category == toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER && eval.Triggered {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("TOOL_ERROR: expected risk_tier evaluator to trigger for unregistered tool")
	}
}

func TestMCP_ToolError_MisspelledTool(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// "sent_email" instead of "send_email"
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "sent_email",
		ArgumentsJson: `{"to":"alice","subject":"Hi","body":"Hello"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, eval := range resp.Evaluations {
		if eval.Category == toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER && eval.Triggered {
			return // pass
		}
	}
	t.Fatal("TOOL_ERROR: expected risk_tier evaluator to flag misspelled tool name")
}

// ---------------------------------------------------------------------------
// PARAM_NAME_ERROR — correct tool, but param names are wrong/missing/extra
// ---------------------------------------------------------------------------

func TestMCP_ParamNameError_MissingRequiredParam(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// Missing "quantity" (required)
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "order_food",
		ArgumentsJson: `{"item_name":"Margherita Pizza"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("PARAM_NAME_ERROR: expected UNSAFE for missing required param, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_ParamNameError_WrongParamName(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// "item" instead of "item_name", "qty" instead of "quantity"
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "order_food",
		ArgumentsJson: `{"item":"Margherita Pizza","qty":2}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("PARAM_NAME_ERROR: expected UNSAFE for wrong param names, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_ParamNameError_ExtraParams(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// Extra param "notes" not in schema (additionalProperties: false)
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "order_food",
		ArgumentsJson: `{"item_name":"Margherita Pizza","quantity":2,"notes":"extra cheese"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("PARAM_NAME_ERROR: expected UNSAFE for extra params, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_ParamNameError_SendEmail_MissingBody(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// Missing "body" (required)
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "send_email",
		ArgumentsJson: `{"to":"alice","subject":"Hello"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("PARAM_NAME_ERROR: expected UNSAFE for missing body, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

// ---------------------------------------------------------------------------
// PARAM_VALUE_ERROR — tool and params correct, but values are wrong type/format
// ---------------------------------------------------------------------------

func TestMCP_ParamValueError_WrongType(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// quantity should be integer, got string
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "order_food",
		ArgumentsJson: `{"item_name":"Margherita Pizza","quantity":"two"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("PARAM_VALUE_ERROR: expected UNSAFE for wrong type, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_ParamValueError_InvalidEnum(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// "kelvin" not in enum ["celsius", "fahrenheit"]
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "get_weather",
		ArgumentsJson: `{"location":"Tokyo","unit":"kelvin"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("PARAM_VALUE_ERROR: expected UNSAFE for invalid enum value, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_ParamValueError_InvalidCurrency(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// "BTC" not in currency enum
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "transfer_funds",
		ArgumentsJson: `{"from_account":"acc-123","to_account":"acc-456","amount":50.00,"currency":"BTC"}`,
		UserConfirmed: true,
		Trace: []*toolguardv1.TraceEntry{
			{ToolName: "authenticate_user", ResultJson: `{"ok":true}`},
			{ToolName: "get_account", ResultJson: `{"account_id":"acc-123"}`},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("PARAM_VALUE_ERROR: expected UNSAFE for invalid currency, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_ParamValueError_TraceBindingMismatch(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// from_account="acc-999" but trace says get_account returned "acc-123"
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "transfer_funds",
		ArgumentsJson: `{"from_account":"acc-999","to_account":"acc-456","amount":50.00,"currency":"USD"}`,
		UserConfirmed: true,
		Trace: []*toolguardv1.TraceEntry{
			{ToolName: "authenticate_user", ResultJson: `{"ok":true}`},
			{ToolName: "get_account", ResultJson: `{"account_id":"acc-123"}`},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("PARAM_VALUE_ERROR: expected UNSAFE for trace binding mismatch, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_ParamValueError_InjectionInValue(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// SQL injection in the item_name value
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "order_food",
		ArgumentsJson: `{"item_name":"'; DROP TABLE orders; --","quantity":1}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	// injection scanning should catch this
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("PARAM_VALUE_ERROR: expected UNSAFE for injection in value, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_ParamValueError_PIIInEmailBody(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// SSN in email body
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "send_email",
		ArgumentsJson: `{"to":"bob","subject":"Info","body":"My SSN is 123-45-6789"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("PARAM_VALUE_ERROR: expected UNSAFE for PII in value, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

// ---------------------------------------------------------------------------
// Combined scenarios — multiple error types in one call
// ---------------------------------------------------------------------------

func TestMCP_Combined_ToolErrorPlusInjection(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// Wrong tool name + injection in args
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "execute_query",
		ArgumentsJson: `{"sql":"SELECT * FROM users; DROP TABLE users"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("COMBINED: expected UNSAFE, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestMCP_Combined_MissingPreconditionsPlusWrongParams(t *testing.T) {
	client, cleanup := setupTestServer(t, mcpToolRegistry())
	defer cleanup()

	// transfer_funds without preconditions + wrong currency enum
	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "transfer_funds",
		ArgumentsJson: `{"from_account":"acc-123","to_account":"acc-456","amount":50.00,"currency":"YEN"}`,
		UserConfirmed: true,
		Trace:         nil, // no preconditions met
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("COMBINED: expected UNSAFE, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}

	// Should have multiple evaluators triggered
	triggeredCount := 0
	for _, eval := range resp.Evaluations {
		if eval.Triggered && eval.Confidence >= 0.8 {
			triggeredCount++
		}
	}
	if triggeredCount < 2 {
		t.Fatalf("COMBINED: expected at least 2 evaluators triggered, got %d", triggeredCount)
	}
}
