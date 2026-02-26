package engine

import (
	"context"
	"time"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"go.uber.org/zap"
)

// ToolGuardEngine fans out evaluation requests to all registered evaluators
// in parallel and collects their results.
type ToolGuardEngine struct {
	evaluators []Evaluator
	timeout    time.Duration
	logger     *zap.Logger
}

// NewToolGuardEngine creates an engine with the given evaluators and timeout.
func NewToolGuardEngine(evaluators []Evaluator, timeout time.Duration, logger *zap.Logger) *ToolGuardEngine {
	return &ToolGuardEngine{
		evaluators: evaluators,
		timeout:    timeout,
		logger:     logger,
	}
}

// evalOutput holds a single evaluator's result alongside its metadata.
type evalOutput struct {
	name     string
	category toolguardv1.EvalCategory
	result   *EvalResult
	err      error
}

// Evaluate runs evaluators in parallel against the request and returns
// the collected results. Evaluators that exceed the timeout are skipped.
//
// Each goroutine sends its result through a buffered channel, so the main
// goroutine can safely read completed results without racing against
// in-flight writes. When the deadline fires, we stop reading and return
// whatever has been collected.
func (e *ToolGuardEngine) Evaluate(ctx context.Context, req *EvalRequest) ([]*toolguardv1.EvalResult, time.Duration) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	ch := make(chan evalOutput, len(e.evaluators))

	for _, ev := range e.evaluators {
		go func(ev Evaluator) {
			result, err := ev.Evaluate(ctx, req)
			ch <- evalOutput{
				name:     ev.Name(),
				category: ev.Category(),
				result:   result,
				err:      err,
			}
		}(ev)
	}

	collected := make([]evalOutput, 0, len(e.evaluators))
	remaining := len(e.evaluators)
	for remaining > 0 {
		select {
		case out := <-ch:
			collected = append(collected, out)
			remaining--
		case <-ctx.Done():
			e.logger.Warn("evaluator timeout exceeded, returning partial results",
				zap.Duration("timeout", e.timeout),
			)
			remaining = 0
		}
	}

	results := make([]*toolguardv1.EvalResult, 0, len(collected))
	for _, out := range collected {
		if out.err != nil {
			e.logger.Warn("evaluator error",
				zap.String("evaluator", out.name),
				zap.Error(out.err),
			)
			results = append(results, &toolguardv1.EvalResult{
				Category:   out.category,
				Triggered:  false,
				Confidence: 0,
				Details:    "evaluator error: " + out.err.Error(),
			})
			continue
		}
		if out.result == nil {
			continue
		}
		results = append(results, &toolguardv1.EvalResult{
			Category:   out.category,
			Triggered:  out.result.Triggered,
			Confidence: out.result.Confidence,
			Details:    out.result.Details,
		})
	}

	return results, time.Since(start)
}
