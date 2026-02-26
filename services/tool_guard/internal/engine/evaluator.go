package engine

import (
	"context"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/registry"
)

// Evaluator is the interface every safety evaluator must implement.
// Implementations must respect context deadlines and return quickly.
type Evaluator interface {
	// Name returns the evaluator's unique identifier.
	Name() string

	// Category returns the evaluation category.
	Category() toolguardv1.EvalCategory

	// Evaluate runs the evaluation logic against the given request.
	// Must respect ctx deadline. Return early if ctx is cancelled.
	Evaluate(ctx context.Context, req *EvalRequest) (*EvalResult, error)
}

// EvalRequest contains all the context needed for evaluation.
type EvalRequest struct {
	ToolName      string
	ArgumentsJSON string
	Trace         []*toolguardv1.TraceEntry
	UserConfirmed bool
	WorkflowType  string
	ToolDef       *registry.ToolDefinition // nil for unregistered tools
}

// EvalResult is the outcome of a single evaluator run.
type EvalResult struct {
	Triggered  bool
	Confidence float32 // 0.0 – 1.0
	Details    string
}
