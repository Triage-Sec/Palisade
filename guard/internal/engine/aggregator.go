package engine

import (
	"strings"

	guardv1 "github.com/triage-ai/palisade/gen/guard/v1"
)

// AggregatorConfig holds the thresholds for verdict determination.
type AggregatorConfig struct {
	BlockThreshold float32 // Confidence >= this → BLOCK (default 0.8)
	FlagThreshold  float32 // Confidence >= this but < BlockThreshold → FLAG (default 0.0)
}

// DefaultAggregatorConfig returns the hardcoded Phase 1 thresholds.
func DefaultAggregatorConfig() AggregatorConfig {
	return AggregatorConfig{
		BlockThreshold: 0.8,
		FlagThreshold:  0.0,
	}
}

// AggregateResult holds the final verdict and reason after aggregation.
type AggregateResult struct {
	Verdict guardv1.Verdict
	Reason  string
}

// Aggregate takes detector results and applies threshold rules to produce a verdict.
//
// Rules (applied in order):
//  1. If ANY detector has Triggered=true AND Confidence >= BlockThreshold → BLOCK
//  2. If ANY detector has Triggered=true AND Confidence < BlockThreshold  → FLAG
//  3. Otherwise → ALLOW
func Aggregate(results []*guardv1.DetectorResult, cfg AggregatorConfig) AggregateResult {
	verdict := guardv1.Verdict_VERDICT_ALLOW
	var triggeredNames []string

	for _, r := range results {
		if !r.Triggered {
			continue
		}

		triggeredNames = append(triggeredNames, r.Detector)

		if r.Confidence >= cfg.BlockThreshold {
			verdict = guardv1.Verdict_VERDICT_BLOCK
		} else if r.Confidence >= cfg.FlagThreshold && verdict != guardv1.Verdict_VERDICT_BLOCK {
			verdict = guardv1.Verdict_VERDICT_FLAG
		}
	}

	reason := ""
	if len(triggeredNames) > 0 {
		reason = "triggered: " + strings.Join(triggeredNames, ", ")
	}

	return AggregateResult{
		Verdict: verdict,
		Reason:  reason,
	}
}
