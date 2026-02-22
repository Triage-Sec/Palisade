package engine

import (
	"context"
	"sync"
	"time"

	guardv1 "github.com/triage-ai/palisade/gen/guard/v1"
	"go.uber.org/zap"
)

// SentryEngine fans out detection requests to all registered detectors
// in parallel and aggregates their results into a verdict.
type SentryEngine struct {
	detectors []Detector
	timeout   time.Duration
	logger    *zap.Logger
}

// NewSentryEngine creates an engine with the given detectors and timeout.
func NewSentryEngine(detectors []Detector, timeout time.Duration, logger *zap.Logger) *SentryEngine {
	return &SentryEngine{
		detectors: detectors,
		timeout:   timeout,
		logger:    logger,
	}
}

// detectorOutput holds a single detector's result alongside its metadata.
type detectorOutput struct {
	name     string
	category guardv1.ThreatCategory
	result   *DetectResult
	err      error
}

// Evaluate runs all detectors in parallel against the request and returns
// the aggregated results. Detectors that exceed the timeout are skipped.
//
// The timeout is enforced at the Evaluate level: if the deadline fires before
// all goroutines finish, Evaluate returns immediately with whatever results
// have been written so far. Slow goroutines keep running in the background
// (Go doesn't allow killing goroutines) but their results are never read —
// each goroutine writes to its own pre-allocated index in the outputs slice,
// so there are no data races.
func (e *SentryEngine) Evaluate(ctx context.Context, req *DetectRequest) ([]*guardv1.DetectorResult, time.Duration) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	outputs := make([]detectorOutput, len(e.detectors))
	var wg sync.WaitGroup
	wg.Add(len(e.detectors))

	for i, det := range e.detectors {
		go func(idx int, d Detector) {
			defer wg.Done()
			result, err := d.Detect(ctx, req)
			outputs[idx] = detectorOutput{
				name:     d.Name(),
				category: d.Category(),
				result:   result,
				err:      err,
			}
		}(i, det)
	}

	// Race the WaitGroup against the context deadline. If the deadline fires
	// first, we return with whatever outputs have been written so far.
	// Unfinished goroutines will have zero-value detectorOutput entries
	// (name="" and result=nil), which are skipped below.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All detectors finished within the deadline.
	case <-ctx.Done():
		// Deadline exceeded — proceed with partial results.
		e.logger.Warn("detector timeout exceeded, returning partial results",
			zap.Duration("timeout", e.timeout),
		)
	}

	results := make([]*guardv1.DetectorResult, 0, len(e.detectors))
	for _, out := range outputs {
		if out.name == "" {
			// Goroutine hasn't written yet (timed out) — treat as not triggered.
			continue
		}
		if out.err != nil {
			e.logger.Warn("detector error",
				zap.String("detector", out.name),
				zap.Error(out.err),
			)
			results = append(results, &guardv1.DetectorResult{
				Detector:   out.name,
				Triggered:  false,
				Confidence: 0,
				Category:   out.category,
				Details:    "detector error: " + out.err.Error(),
			})
			continue
		}
		if out.result == nil {
			continue
		}
		results = append(results, &guardv1.DetectorResult{
			Detector:   out.name,
			Triggered:  out.result.Triggered,
			Confidence: out.result.Confidence,
			Category:   out.category,
			Details:    out.result.Details,
		})
	}

	return results, time.Since(start)
}
