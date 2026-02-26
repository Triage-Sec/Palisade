package evaluators

import (
	"context"
	"fmt"
	"time"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
)

// ContextualRulesEvaluator checks workflow constraints and rate limits.
type ContextualRulesEvaluator struct{}

func NewContextualRulesEvaluator() *ContextualRulesEvaluator {
	return &ContextualRulesEvaluator{}
}

func (e *ContextualRulesEvaluator) Name() string {
	return "contextual_rules"
}

func (e *ContextualRulesEvaluator) Category() toolguardv1.EvalCategory {
	return toolguardv1.EvalCategory_EVAL_CATEGORY_CONTEXTUAL_RULES
}

func (e *ContextualRulesEvaluator) Evaluate(_ context.Context, req *engine.EvalRequest) (*engine.EvalResult, error) {
	if req.ToolDef == nil {
		return &engine.EvalResult{Triggered: false}, nil
	}

	rules := req.ToolDef.ContextualRules

	// 1. Blocked workflows check
	if req.WorkflowType != "" && len(rules.BlockedWorkflows) > 0 {
		for _, blocked := range rules.BlockedWorkflows {
			if req.WorkflowType == blocked {
				return &engine.EvalResult{
					Triggered:  true,
					Confidence: 0.95,
					Details:    fmt.Sprintf("tool blocked in workflow: %s", req.WorkflowType),
				}, nil
			}
		}
	}

	// 2. Allowed workflows check (if list is non-empty, workflow must be in it)
	if req.WorkflowType != "" && len(rules.AllowedWorkflows) > 0 {
		found := false
		for _, allowed := range rules.AllowedWorkflows {
			if req.WorkflowType == allowed {
				found = true
				break
			}
		}
		if !found {
			return &engine.EvalResult{
				Triggered:  true,
				Confidence: 0.90,
				Details:    fmt.Sprintf("tool not allowed in workflow: %s", req.WorkflowType),
			}, nil
		}
	}

	// 3. Rate limit check from trace
	if rules.RateLimit != nil && rules.RateLimit.MaxCalls > 0 {
		windowMs := int64(rules.RateLimit.WindowSeconds) * 1000
		nowMs := time.Now().UnixMilli()
		count := 0
		for _, entry := range req.Trace {
			if entry.ToolName == req.ToolName && entry.TimestampMs > 0 {
				if nowMs-entry.TimestampMs <= windowMs {
					count++
				}
			}
		}
		if count >= rules.RateLimit.MaxCalls {
			return &engine.EvalResult{
				Triggered:  true,
				Confidence: 0.90,
				Details:    fmt.Sprintf("rate limit exceeded: %d/%d calls in %ds window", count, rules.RateLimit.MaxCalls, rules.RateLimit.WindowSeconds),
			}, nil
		}
	}

	return &engine.EvalResult{Triggered: false}, nil
}
