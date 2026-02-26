package evaluators

import (
	"context"
	"fmt"
	"strings"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
)

// PreconditionEvaluator verifies that required precondition tools
// have been executed in the trace before this tool call.
type PreconditionEvaluator struct{}

func NewPreconditionEvaluator() *PreconditionEvaluator {
	return &PreconditionEvaluator{}
}

func (e *PreconditionEvaluator) Name() string {
	return "precondition"
}

func (e *PreconditionEvaluator) Category() toolguardv1.EvalCategory {
	return toolguardv1.EvalCategory_EVAL_CATEGORY_PRECONDITION
}

func (e *PreconditionEvaluator) Evaluate(_ context.Context, req *engine.EvalRequest) (*engine.EvalResult, error) {
	if req.ToolDef == nil || len(req.ToolDef.Preconditions) == 0 {
		return &engine.EvalResult{Triggered: false}, nil
	}

	// Build set of tools already called in the trace
	called := make(map[string]bool, len(req.Trace))
	for _, entry := range req.Trace {
		called[entry.ToolName] = true
	}

	// Check each precondition
	var missing []string
	for _, pre := range req.ToolDef.Preconditions {
		if !called[pre] {
			missing = append(missing, pre)
		}
	}

	if len(missing) > 0 {
		return &engine.EvalResult{
			Triggered:  true,
			Confidence: 0.95,
			Details:    fmt.Sprintf("missing preconditions: %s", strings.Join(missing, ", ")),
		}, nil
	}

	return &engine.EvalResult{Triggered: false}, nil
}
