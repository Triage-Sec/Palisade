package engine

import (
	"strings"
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
	Verdict Verdict
	Reason  string
}

// Aggregate takes detector results and applies global threshold rules to produce a verdict.
// This is a convenience wrapper that calls AggregateWithPolicy with a nil policy.
func Aggregate(results []*DetectorResult, cfg AggregatorConfig) AggregateResult {
	return AggregateWithPolicy(results, cfg, nil)
}

// AggregateWithPolicy applies per-detector thresholds from the policy to produce a verdict.
// For each triggered detector, it looks up that detector's thresholds from the policy,
// falling back to the server defaults in cfg when the policy is nil or has no entry.
//
// Rules (applied in order):
//  1. If ANY detector has Triggered=true AND Confidence >= its block_threshold → BLOCK
//  2. If ANY detector has Triggered=true AND Confidence >= its flag_threshold  → FLAG
//  3. Otherwise → ALLOW
func AggregateWithPolicy(results []*DetectorResult, cfg AggregatorConfig, policy *PolicyConfig) AggregateResult {
	verdict := VerdictAllow
	var triggeredNames []string

	for _, r := range results {
		if !r.Triggered {
			continue
		}

		triggeredNames = append(triggeredNames, r.Detector)

		dp := policy.GetDetectorPolicy(r.Detector)
		blockThreshold := dp.EffectiveBlockThreshold(cfg.BlockThreshold)
		flagThreshold := dp.EffectiveFlagThreshold(cfg.FlagThreshold)

		if r.Confidence >= blockThreshold {
			verdict = VerdictBlock
		} else if r.Confidence >= flagThreshold && verdict != VerdictBlock {
			verdict = VerdictFlag
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
