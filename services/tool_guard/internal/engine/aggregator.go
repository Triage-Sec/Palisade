package engine

import (
	"strings"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
)

// AggregatorConfig holds the threshold for verdict determination.
type AggregatorConfig struct {
	UnsafeThreshold float32 // Confidence >= this → UNSAFE (default 0.8)
}

// DefaultAggregatorConfig returns the default thresholds.
func DefaultAggregatorConfig() AggregatorConfig {
	return AggregatorConfig{
		UnsafeThreshold: 0.8,
	}
}

// AggregateResult holds the final verdict and reason after aggregation.
type AggregateResult struct {
	Verdict            toolguardv1.SafetyVerdict
	Reason             string
	OutputRestrictions []string
}

// Aggregate takes evaluator results and applies threshold rules to produce a verdict.
//
// Rules (applied in order):
//  1. If ANY evaluator triggered with confidence >= UnsafeThreshold → UNSAFE
//  2. If risk_tier evaluator triggered with "requires confirmation" detail → NEEDS_CONFIRMATION
//  3. Otherwise → SAFE
//
// UNSAFE overrides NEEDS_CONFIRMATION.
func Aggregate(results []*toolguardv1.EvalResult, cfg AggregatorConfig) AggregateResult {
	verdict := toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE
	var triggeredDetails []string
	needsConfirm := false

	for _, r := range results {
		if !r.Triggered {
			continue
		}

		triggeredDetails = append(triggeredDetails, r.Details)

		if r.Confidence >= cfg.UnsafeThreshold {
			// Check if this is a "needs confirmation" trigger from risk_tier
			if r.Category == toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER &&
				strings.Contains(r.Details, "requires user confirmation") {
				needsConfirm = true
			} else {
				verdict = toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE
			}
		}
	}

	// UNSAFE overrides NEEDS_CONFIRMATION
	if verdict == toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		// keep UNSAFE
	} else if needsConfirm {
		verdict = toolguardv1.SafetyVerdict_SAFETY_VERDICT_NEEDS_CONFIRMATION
	}

	reason := ""
	if len(triggeredDetails) > 0 {
		reason = strings.Join(triggeredDetails, "; ")
	}

	return AggregateResult{
		Verdict: verdict,
		Reason:  reason,
	}
}
