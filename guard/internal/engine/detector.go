package engine

import (
	"context"
)

// Detector is the interface every security detector must implement.
// Implementations must respect context deadlines and return quickly.
type Detector interface {
	// Name returns the detector's unique identifier (e.g., "prompt_injection").
	Name() string

	// Category returns the threat category this detector covers.
	Category() ThreatCategory

	// Detect runs the detection logic against the given request.
	// Must respect ctx deadline. Return early if ctx is cancelled.
	Detect(ctx context.Context, req *DetectRequest) (*DetectResult, error)
}

// DetectRequest contains the payload and context for a detection run.
type DetectRequest struct {
	Payload       string
	Action        ActionType
	ToolCall      *ToolCall // nil unless action == ActionToolCall
	ToolAllowList []string  // Per-project tool allowlist (set by engine from policy)
	ToolBlockList []string  // Per-project tool blocklist (set by engine from policy)
}

// DetectResult is the outcome of a single detector run.
type DetectResult struct {
	Triggered  bool
	Confidence float32 // 0.0 – 1.0
	Details    string
}
