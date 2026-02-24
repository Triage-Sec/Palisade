package engine

// PolicyConfig represents per-project detector configuration.
// Loaded from the policies table's detector_config JSONB column.
type PolicyConfig struct {
	Detectors map[string]DetectorPolicy `json:"detectors"`
}

// GetDetectorPolicy returns the policy for a detector by name.
// If the PolicyConfig is nil or the detector is missing, returns
// a zero-value DetectorPolicy (all nil fields → server defaults).
func (pc *PolicyConfig) GetDetectorPolicy(detectorName string) DetectorPolicy {
	if pc == nil || pc.Detectors == nil {
		return DetectorPolicy{}
	}
	return pc.Detectors[detectorName]
}

// DetectorPolicy controls behavior of a single detector for a project.
// All pointer fields use nil to mean "use server default".
type DetectorPolicy struct {
	Enabled        *bool    `json:"enabled"`         // nil = use server default (true)
	BlockThreshold *float32 `json:"block_threshold"` // nil = use server default (0.8)
	FlagThreshold  *float32 `json:"flag_threshold"`  // nil = use server default (0.0)
	AllowedTools   []string `json:"allowed_tools"`   // tool_abuse only
	BlockedTools   []string `json:"blocked_tools"`   // tool_abuse only
}

// IsEnabled returns whether the detector is enabled.
// A nil Enabled field defaults to true (all detectors on by default).
func (dp DetectorPolicy) IsEnabled() bool {
	if dp.Enabled == nil {
		return true
	}
	return *dp.Enabled
}

// EffectiveBlockThreshold returns the block threshold for this detector.
// A nil BlockThreshold falls back to the provided server default.
func (dp DetectorPolicy) EffectiveBlockThreshold(serverDefault float32) float32 {
	if dp.BlockThreshold == nil {
		return serverDefault
	}
	return *dp.BlockThreshold
}

// EffectiveFlagThreshold returns the flag threshold for this detector.
// A nil FlagThreshold falls back to the provided server default.
func (dp DetectorPolicy) EffectiveFlagThreshold(serverDefault float32) float32 {
	if dp.FlagThreshold == nil {
		return serverDefault
	}
	return *dp.FlagThreshold
}
