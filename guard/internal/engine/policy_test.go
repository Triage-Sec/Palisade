package engine

import (
	"encoding/json"
	"testing"
)

func boolPtr(b bool) *bool       { return &b }
func float32Ptr(f float32) *float32 { return &f }

func TestDetectorPolicy_IsEnabled_NilDefaultsTrue(t *testing.T) {
	dp := DetectorPolicy{}
	if !dp.IsEnabled() {
		t.Error("nil Enabled should default to true")
	}
}

func TestDetectorPolicy_IsEnabled_ExplicitFalse(t *testing.T) {
	dp := DetectorPolicy{Enabled: boolPtr(false)}
	if dp.IsEnabled() {
		t.Error("explicit false should return false")
	}
}

func TestDetectorPolicy_IsEnabled_ExplicitTrue(t *testing.T) {
	dp := DetectorPolicy{Enabled: boolPtr(true)}
	if !dp.IsEnabled() {
		t.Error("explicit true should return true")
	}
}

func TestDetectorPolicy_EffectiveBlockThreshold_Nil(t *testing.T) {
	dp := DetectorPolicy{}
	if got := dp.EffectiveBlockThreshold(0.8); got != 0.8 {
		t.Errorf("nil BlockThreshold should return server default 0.8, got %f", got)
	}
}

func TestDetectorPolicy_EffectiveBlockThreshold_Custom(t *testing.T) {
	dp := DetectorPolicy{BlockThreshold: float32Ptr(0.95)}
	if got := dp.EffectiveBlockThreshold(0.8); got != 0.95 {
		t.Errorf("custom BlockThreshold should return 0.95, got %f", got)
	}
}

func TestDetectorPolicy_EffectiveFlagThreshold_Nil(t *testing.T) {
	dp := DetectorPolicy{}
	if got := dp.EffectiveFlagThreshold(0.0); got != 0.0 {
		t.Errorf("nil FlagThreshold should return server default 0.0, got %f", got)
	}
}

func TestDetectorPolicy_EffectiveFlagThreshold_Custom(t *testing.T) {
	dp := DetectorPolicy{FlagThreshold: float32Ptr(0.5)}
	if got := dp.EffectiveFlagThreshold(0.0); got != 0.5 {
		t.Errorf("custom FlagThreshold should return 0.5, got %f", got)
	}
}

func TestPolicyConfig_NilReturnsDefaults(t *testing.T) {
	var pc *PolicyConfig
	dp := pc.GetDetectorPolicy("prompt_injection")

	if !dp.IsEnabled() {
		t.Error("nil PolicyConfig should return enabled=true by default")
	}
	if dp.BlockThreshold != nil {
		t.Error("nil PolicyConfig should return nil BlockThreshold")
	}
	if dp.FlagThreshold != nil {
		t.Error("nil PolicyConfig should return nil FlagThreshold")
	}
}

func TestPolicyConfig_MissingDetectorReturnsDefaults(t *testing.T) {
	pc := &PolicyConfig{
		Detectors: map[string]DetectorPolicy{
			"pii": {Enabled: boolPtr(false)},
		},
	}

	dp := pc.GetDetectorPolicy("prompt_injection")
	if !dp.IsEnabled() {
		t.Error("missing detector should default to enabled=true")
	}
	if dp.EffectiveBlockThreshold(0.8) != 0.8 {
		t.Error("missing detector should use server default block threshold")
	}
}

func TestPolicyConfig_ExplicitDisabled(t *testing.T) {
	pc := &PolicyConfig{
		Detectors: map[string]DetectorPolicy{
			"pii": {Enabled: boolPtr(false)},
		},
	}

	dp := pc.GetDetectorPolicy("pii")
	if dp.IsEnabled() {
		t.Error("explicit enabled=false should return false")
	}
}

func TestPolicyConfig_CustomThresholdsOverrideDefaults(t *testing.T) {
	pc := &PolicyConfig{
		Detectors: map[string]DetectorPolicy{
			"prompt_injection": {
				BlockThreshold: float32Ptr(0.95),
				FlagThreshold:  float32Ptr(0.3),
			},
		},
	}

	dp := pc.GetDetectorPolicy("prompt_injection")
	if got := dp.EffectiveBlockThreshold(0.8); got != 0.95 {
		t.Errorf("expected custom block threshold 0.95, got %f", got)
	}
	if got := dp.EffectiveFlagThreshold(0.0); got != 0.3 {
		t.Errorf("expected custom flag threshold 0.3, got %f", got)
	}
}

func TestPolicyConfig_NilDetectorsMap(t *testing.T) {
	pc := &PolicyConfig{Detectors: nil}
	dp := pc.GetDetectorPolicy("anything")

	if !dp.IsEnabled() {
		t.Error("nil Detectors map should return enabled=true by default")
	}
}

func TestPolicyConfig_ToolAbusePolicy(t *testing.T) {
	pc := &PolicyConfig{
		Detectors: map[string]DetectorPolicy{
			"tool_abuse": {
				AllowedTools: []string{"search", "calculator"},
				BlockedTools: []string{"exec", "eval"},
			},
		},
	}

	dp := pc.GetDetectorPolicy("tool_abuse")
	if len(dp.AllowedTools) != 2 || dp.AllowedTools[0] != "search" {
		t.Errorf("expected AllowedTools [search, calculator], got %v", dp.AllowedTools)
	}
	if len(dp.BlockedTools) != 2 || dp.BlockedTools[0] != "exec" {
		t.Errorf("expected BlockedTools [exec, eval], got %v", dp.BlockedTools)
	}
}

func TestPolicyConfig_JSONRoundTrip(t *testing.T) {
	input := `{
		"detectors": {
			"prompt_injection": {
				"enabled": true,
				"block_threshold": 0.9,
				"flag_threshold": 0.0
			},
			"pii": {
				"enabled": false
			},
			"tool_abuse": {
				"enabled": true,
				"allowed_tools": ["search", "calculator"],
				"blocked_tools": ["exec", "eval"]
			}
		}
	}`

	var pc PolicyConfig
	if err := json.Unmarshal([]byte(input), &pc); err != nil {
		t.Fatalf("failed to unmarshal PolicyConfig: %v", err)
	}

	// prompt_injection
	pi := pc.GetDetectorPolicy("prompt_injection")
	if !pi.IsEnabled() {
		t.Error("prompt_injection should be enabled")
	}
	if got := pi.EffectiveBlockThreshold(0.8); got != 0.9 {
		t.Errorf("prompt_injection block_threshold: expected 0.9, got %f", got)
	}

	// pii — disabled
	pii := pc.GetDetectorPolicy("pii")
	if pii.IsEnabled() {
		t.Error("pii should be disabled")
	}

	// tool_abuse — tools lists
	ta := pc.GetDetectorPolicy("tool_abuse")
	if !ta.IsEnabled() {
		t.Error("tool_abuse should be enabled")
	}
	if len(ta.AllowedTools) != 2 {
		t.Errorf("tool_abuse expected 2 allowed tools, got %d", len(ta.AllowedTools))
	}
	if len(ta.BlockedTools) != 2 {
		t.Errorf("tool_abuse expected 2 blocked tools, got %d", len(ta.BlockedTools))
	}

	// unknown detector — defaults
	unknown := pc.GetDetectorPolicy("nonexistent")
	if !unknown.IsEnabled() {
		t.Error("unknown detector should default to enabled")
	}
}
