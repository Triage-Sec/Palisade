package engine

import (
	"testing"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
)

func TestAggregate_AllSafe(t *testing.T) {
	results := []*toolguardv1.EvalResult{
		{Category: toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER, Triggered: false},
		{Category: toolguardv1.EvalCategory_EVAL_CATEGORY_PRECONDITION, Triggered: false},
	}
	agg := Aggregate(results, DefaultAggregatorConfig())
	if agg.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE {
		t.Fatalf("expected SAFE, got %v", agg.Verdict)
	}
}

func TestAggregate_UnsafeOnHighConfidence(t *testing.T) {
	results := []*toolguardv1.EvalResult{
		{
			Category:   toolguardv1.EvalCategory_EVAL_CATEGORY_PRECONDITION,
			Triggered:  true,
			Confidence: 0.95,
			Details:    "missing preconditions: authenticate_user",
		},
	}
	agg := Aggregate(results, DefaultAggregatorConfig())
	if agg.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("expected UNSAFE, got %v", agg.Verdict)
	}
}

func TestAggregate_SafeOnLowConfidence(t *testing.T) {
	results := []*toolguardv1.EvalResult{
		{
			Category:   toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER,
			Triggered:  true,
			Confidence: 0.5,
			Details:    "unregistered tool: unknown",
		},
	}
	agg := Aggregate(results, DefaultAggregatorConfig())
	if agg.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE {
		t.Fatalf("expected SAFE for low confidence trigger, got %v", agg.Verdict)
	}
}

func TestAggregate_NeedsConfirmation(t *testing.T) {
	results := []*toolguardv1.EvalResult{
		{
			Category:   toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER,
			Triggered:  true,
			Confidence: 0.95,
			Details:    "destructive tool requires user confirmation",
		},
	}
	agg := Aggregate(results, DefaultAggregatorConfig())
	if agg.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_NEEDS_CONFIRMATION {
		t.Fatalf("expected NEEDS_CONFIRMATION, got %v", agg.Verdict)
	}
}

func TestAggregate_UnsafeOverridesNeedsConfirmation(t *testing.T) {
	results := []*toolguardv1.EvalResult{
		{
			Category:   toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER,
			Triggered:  true,
			Confidence: 0.95,
			Details:    "destructive tool requires user confirmation",
		},
		{
			Category:   toolguardv1.EvalCategory_EVAL_CATEGORY_PRECONDITION,
			Triggered:  true,
			Confidence: 0.95,
			Details:    "missing preconditions: authenticate_user",
		},
	}
	agg := Aggregate(results, DefaultAggregatorConfig())
	if agg.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("expected UNSAFE to override NEEDS_CONFIRMATION, got %v", agg.Verdict)
	}
}

func TestAggregate_EmptyResults(t *testing.T) {
	agg := Aggregate(nil, DefaultAggregatorConfig())
	if agg.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE {
		t.Fatalf("expected SAFE for empty results, got %v", agg.Verdict)
	}
	if agg.Reason != "" {
		t.Fatalf("expected empty reason, got %s", agg.Reason)
	}
}

func TestAggregate_CustomThreshold(t *testing.T) {
	results := []*toolguardv1.EvalResult{
		{
			Category:   toolguardv1.EvalCategory_EVAL_CATEGORY_ARGUMENT_VALIDATION,
			Triggered:  true,
			Confidence: 0.85,
			Details:    "injection detected",
		},
	}
	// With threshold at 0.9, confidence 0.85 should be SAFE
	agg := Aggregate(results, AggregatorConfig{UnsafeThreshold: 0.9})
	if agg.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE {
		t.Fatalf("expected SAFE with higher threshold, got %v", agg.Verdict)
	}
}
