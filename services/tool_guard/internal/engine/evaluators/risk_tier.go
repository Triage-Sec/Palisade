package evaluators

import (
	"context"
	"fmt"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
)

// RiskTierEvaluator checks the tool's risk tier and confirmation requirements.
type RiskTierEvaluator struct{}

func NewRiskTierEvaluator() *RiskTierEvaluator {
	return &RiskTierEvaluator{}
}

func (e *RiskTierEvaluator) Name() string {
	return "risk_tier"
}

func (e *RiskTierEvaluator) Category() toolguardv1.EvalCategory {
	return toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER
}

func (e *RiskTierEvaluator) Evaluate(_ context.Context, req *engine.EvalRequest) (*engine.EvalResult, error) {
	if req.ToolDef == nil {
		// Unregistered tool: low confidence trigger (below default 0.8 threshold → SAFE)
		return &engine.EvalResult{
			Triggered:  true,
			Confidence: 0.5,
			Details:    fmt.Sprintf("unregistered tool: %s", req.ToolName),
		}, nil
	}

	td := req.ToolDef

	// Destructive tool that requires confirmation but user hasn't confirmed
	if td.RiskTier == "destructive" && td.RequiresConfirm && !req.UserConfirmed {
		return &engine.EvalResult{
			Triggered:  true,
			Confidence: 0.95,
			Details:    "destructive tool requires user confirmation",
		}, nil
	}

	return &engine.EvalResult{Triggered: false}, nil
}
