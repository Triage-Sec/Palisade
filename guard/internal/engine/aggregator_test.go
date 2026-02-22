package engine

import (
	"testing"

	guardv1 "github.com/triage-ai/palisade/gen/guard/v1"
)

func TestAggregate_AllClear(t *testing.T) {
	cfg := DefaultAggregatorConfig()
	results := []*guardv1.DetectorResult{
		{Detector: "prompt_injection", Triggered: false, Confidence: 0},
		{Detector: "pii", Triggered: false, Confidence: 0},
		{Detector: "jailbreak", Triggered: false, Confidence: 0},
	}

	agg := Aggregate(results, cfg)
	if agg.Verdict != guardv1.Verdict_VERDICT_ALLOW {
		t.Errorf("expected ALLOW, got %v", agg.Verdict)
	}
	if agg.Reason != "" {
		t.Errorf("expected empty reason, got: %s", agg.Reason)
	}
}

func TestAggregate_SingleBlock(t *testing.T) {
	cfg := DefaultAggregatorConfig()
	results := []*guardv1.DetectorResult{
		{Detector: "prompt_injection", Triggered: true, Confidence: 0.95},
		{Detector: "pii", Triggered: false, Confidence: 0},
		{Detector: "jailbreak", Triggered: false, Confidence: 0},
	}

	agg := Aggregate(results, cfg)
	if agg.Verdict != guardv1.Verdict_VERDICT_BLOCK {
		t.Errorf("expected BLOCK, got %v", agg.Verdict)
	}
	if agg.Reason != "triggered: prompt_injection" {
		t.Errorf("unexpected reason: %s", agg.Reason)
	}
}

func TestAggregate_SingleFlag(t *testing.T) {
	cfg := DefaultAggregatorConfig()
	results := []*guardv1.DetectorResult{
		{Detector: "prompt_injection", Triggered: true, Confidence: 0.5},
		{Detector: "pii", Triggered: false, Confidence: 0},
	}

	agg := Aggregate(results, cfg)
	if agg.Verdict != guardv1.Verdict_VERDICT_FLAG {
		t.Errorf("expected FLAG, got %v", agg.Verdict)
	}
}

func TestAggregate_BlockOverridesFlag(t *testing.T) {
	cfg := DefaultAggregatorConfig()
	results := []*guardv1.DetectorResult{
		{Detector: "prompt_injection", Triggered: true, Confidence: 0.5},  // FLAG-level
		{Detector: "pii", Triggered: true, Confidence: 0.9},              // BLOCK-level
		{Detector: "jailbreak", Triggered: true, Confidence: 0.3},        // FLAG-level
	}

	agg := Aggregate(results, cfg)
	if agg.Verdict != guardv1.Verdict_VERDICT_BLOCK {
		t.Errorf("expected BLOCK (highest wins), got %v", agg.Verdict)
	}
	if agg.Reason != "triggered: prompt_injection, pii, jailbreak" {
		t.Errorf("unexpected reason: %s", agg.Reason)
	}
}

func TestAggregate_ExactBlockThreshold(t *testing.T) {
	cfg := DefaultAggregatorConfig() // BlockThreshold = 0.8
	results := []*guardv1.DetectorResult{
		{Detector: "pii", Triggered: true, Confidence: 0.8}, // Exactly at threshold
	}

	agg := Aggregate(results, cfg)
	if agg.Verdict != guardv1.Verdict_VERDICT_BLOCK {
		t.Errorf("expected BLOCK at exact threshold, got %v", agg.Verdict)
	}
}

func TestAggregate_JustBelowBlockThreshold(t *testing.T) {
	cfg := DefaultAggregatorConfig()
	results := []*guardv1.DetectorResult{
		{Detector: "pii", Triggered: true, Confidence: 0.79},
	}

	agg := Aggregate(results, cfg)
	if agg.Verdict != guardv1.Verdict_VERDICT_FLAG {
		t.Errorf("expected FLAG just below block threshold, got %v", agg.Verdict)
	}
}

func TestAggregate_CustomThresholds(t *testing.T) {
	cfg := AggregatorConfig{
		BlockThreshold: 0.9,
		FlagThreshold:  0.5,
	}
	results := []*guardv1.DetectorResult{
		{Detector: "prompt_injection", Triggered: true, Confidence: 0.85},
	}

	agg := Aggregate(results, cfg)
	// 0.85 >= 0.5 (flag) but < 0.9 (block) → FLAG
	if agg.Verdict != guardv1.Verdict_VERDICT_FLAG {
		t.Errorf("expected FLAG with custom thresholds, got %v", agg.Verdict)
	}
}

func TestAggregate_BelowFlagThreshold(t *testing.T) {
	cfg := AggregatorConfig{
		BlockThreshold: 0.9,
		FlagThreshold:  0.5,
	}
	results := []*guardv1.DetectorResult{
		{Detector: "prompt_injection", Triggered: true, Confidence: 0.3},
	}

	agg := Aggregate(results, cfg)
	// 0.3 < 0.5 (flag threshold) → still ALLOW because below flag threshold
	if agg.Verdict != guardv1.Verdict_VERDICT_ALLOW {
		t.Errorf("expected ALLOW below flag threshold, got %v", agg.Verdict)
	}
}

func TestAggregate_EmptyResults(t *testing.T) {
	cfg := DefaultAggregatorConfig()
	agg := Aggregate(nil, cfg)

	if agg.Verdict != guardv1.Verdict_VERDICT_ALLOW {
		t.Errorf("expected ALLOW for empty results, got %v", agg.Verdict)
	}
}

func TestAggregate_MultipleTriggeredReasons(t *testing.T) {
	cfg := DefaultAggregatorConfig()
	results := []*guardv1.DetectorResult{
		{Detector: "prompt_injection", Triggered: true, Confidence: 0.95},
		{Detector: "jailbreak", Triggered: true, Confidence: 0.90},
		{Detector: "pii", Triggered: false, Confidence: 0},
	}

	agg := Aggregate(results, cfg)
	if agg.Reason != "triggered: prompt_injection, jailbreak" {
		t.Errorf("expected both triggered detectors in reason, got: %s", agg.Reason)
	}
}

func BenchmarkAggregate(b *testing.B) {
	cfg := DefaultAggregatorConfig()
	results := []*guardv1.DetectorResult{
		{Detector: "prompt_injection", Triggered: true, Confidence: 0.95},
		{Detector: "jailbreak", Triggered: false, Confidence: 0},
		{Detector: "pii", Triggered: true, Confidence: 0.5},
		{Detector: "content_mod", Triggered: false, Confidence: 0},
		{Detector: "tool_abuse", Triggered: false, Confidence: 0},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		Aggregate(results, cfg)
	}
}
