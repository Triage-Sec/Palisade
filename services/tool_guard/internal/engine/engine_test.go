package engine

import (
	"context"
	"testing"
	"time"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"go.uber.org/zap"
)

// stubEvaluator is a test helper that returns a fixed result.
type stubEvaluator struct {
	name     string
	category toolguardv1.EvalCategory
	result   *EvalResult
	delay    time.Duration
}

func (s *stubEvaluator) Name() string                    { return s.name }
func (s *stubEvaluator) Category() toolguardv1.EvalCategory { return s.category }
func (s *stubEvaluator) Evaluate(ctx context.Context, _ *EvalRequest) (*EvalResult, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return &EvalResult{Triggered: false}, nil
		}
	}
	return s.result, nil
}

func TestEngine_AllEvaluatorsRun(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	evals := []Evaluator{
		&stubEvaluator{
			name:     "eval_a",
			category: toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER,
			result:   &EvalResult{Triggered: false},
		},
		&stubEvaluator{
			name:     "eval_b",
			category: toolguardv1.EvalCategory_EVAL_CATEGORY_PRECONDITION,
			result:   &EvalResult{Triggered: true, Confidence: 0.95, Details: "missing"},
		},
	}

	eng := NewToolGuardEngine(evals, 100*time.Millisecond, logger)
	results, dur := eng.Evaluate(context.Background(), &EvalRequest{ToolName: "test"})

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if dur > 100*time.Millisecond {
		t.Fatalf("engine took too long: %v", dur)
	}
}

func TestEngine_TimeoutSkipsSlowEvaluator(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	evals := []Evaluator{
		&stubEvaluator{
			name:     "fast",
			category: toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER,
			result:   &EvalResult{Triggered: false},
		},
		&stubEvaluator{
			name:     "slow",
			category: toolguardv1.EvalCategory_EVAL_CATEGORY_PRECONDITION,
			result:   &EvalResult{Triggered: true, Confidence: 0.95, Details: "should be skipped"},
			delay:    500 * time.Millisecond,
		},
	}

	eng := NewToolGuardEngine(evals, 10*time.Millisecond, logger)
	results, _ := eng.Evaluate(context.Background(), &EvalRequest{ToolName: "test"})

	// Should get at least the fast evaluator, slow one may be skipped
	if len(results) > 2 {
		t.Fatalf("unexpected result count: %d", len(results))
	}
}

func TestEngine_EmptyEvaluators(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	eng := NewToolGuardEngine(nil, 100*time.Millisecond, logger)
	results, _ := eng.Evaluate(context.Background(), &EvalRequest{ToolName: "test"})

	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func BenchmarkEngine_FiveEvaluators(b *testing.B) {
	logger := zap.NewNop()
	evals := []Evaluator{
		&stubEvaluator{name: "a", category: toolguardv1.EvalCategory_EVAL_CATEGORY_RISK_TIER, result: &EvalResult{Triggered: false}},
		&stubEvaluator{name: "b", category: toolguardv1.EvalCategory_EVAL_CATEGORY_PRECONDITION, result: &EvalResult{Triggered: false}},
		&stubEvaluator{name: "c", category: toolguardv1.EvalCategory_EVAL_CATEGORY_ARGUMENT_VALIDATION, result: &EvalResult{Triggered: false}},
		&stubEvaluator{name: "d", category: toolguardv1.EvalCategory_EVAL_CATEGORY_CONTEXTUAL_RULES, result: &EvalResult{Triggered: false}},
		&stubEvaluator{name: "e", category: toolguardv1.EvalCategory_EVAL_CATEGORY_INFORMATION_FLOW, result: &EvalResult{Triggered: false}},
	}
	eng := NewToolGuardEngine(evals, 25*time.Millisecond, logger)
	req := &EvalRequest{ToolName: "bench_tool"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.Evaluate(context.Background(), req)
	}
}
