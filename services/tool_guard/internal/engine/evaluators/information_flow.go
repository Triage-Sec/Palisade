package evaluators

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
)

// minSubstringLen is the minimum length for substring matching to avoid false positives.
const minSubstringLen = 4

// InformationFlowEvaluator checks whether tainted data from prior tool outputs
// is flowing into the current tool's arguments.
type InformationFlowEvaluator struct{}

func NewInformationFlowEvaluator() *InformationFlowEvaluator {
	return &InformationFlowEvaluator{}
}

func (e *InformationFlowEvaluator) Name() string {
	return "information_flow"
}

func (e *InformationFlowEvaluator) Category() toolguardv1.EvalCategory {
	return toolguardv1.EvalCategory_EVAL_CATEGORY_INFORMATION_FLOW
}

func (e *InformationFlowEvaluator) Evaluate(ctx context.Context, req *engine.EvalRequest) (*engine.EvalResult, error) {
	if req.ToolDef == nil || len(req.ToolDef.InformationFlow.BlockedSourceLabels) == 0 {
		return &engine.EvalResult{Triggered: false}, nil
	}

	blockedLabels := make(map[string]bool, len(req.ToolDef.InformationFlow.BlockedSourceLabels))
	for _, label := range req.ToolDef.InformationFlow.BlockedSourceLabels {
		blockedLabels[label] = true
	}

	// Find tainted trace entries — those with output_labels matching blocked_source_labels
	var taintedValues []string
	for _, entry := range req.Trace {
		if ctx.Err() != nil {
			break
		}
		if hasTaintedLabel(entry.OutputLabels, blockedLabels) {
			taintedValues = append(taintedValues, extractStringValues(entry.ResultJson)...)
		}
	}

	if len(taintedValues) == 0 {
		return &engine.EvalResult{Triggered: false}, nil
	}

	// Check if any tainted values appear in the current arguments
	var found []string
	for _, val := range taintedValues {
		if ctx.Err() != nil {
			break
		}
		if len(val) >= minSubstringLen && strings.Contains(req.ArgumentsJSON, val) {
			found = append(found, val)
		}
	}

	if len(found) > 0 {
		return &engine.EvalResult{
			Triggered:  true,
			Confidence: 0.90,
			Details:    fmt.Sprintf("tainted data from blocked sources found in arguments (%d values)", len(found)),
		}, nil
	}

	return &engine.EvalResult{Triggered: false}, nil
}

func hasTaintedLabel(outputLabels []string, blockedLabels map[string]bool) bool {
	for _, label := range outputLabels {
		if blockedLabels[label] {
			return true
		}
	}
	return false
}

// extractStringValues extracts all string values from a JSON object/array (shallow).
func extractStringValues(jsonStr string) []string {
	if jsonStr == "" {
		return nil
	}

	var raw any
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		return nil
	}

	var values []string
	collectStrings(raw, &values)
	return values
}

func collectStrings(v any, out *[]string) {
	switch val := v.(type) {
	case string:
		*out = append(*out, val)
	case map[string]any:
		for _, child := range val {
			collectStrings(child, out)
		}
	case []any:
		for _, child := range val {
			collectStrings(child, out)
		}
	}
}
