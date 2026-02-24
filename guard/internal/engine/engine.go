package engine

import (
	"context"
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

// Evaluate runs detectors in parallel against the request and returns
// the aggregated results. Detectors that exceed the timeout are skipped.
//
// If policy is non-nil, detectors disabled by the policy are skipped entirely.
// For the tool_abuse detector, per-project ToolAllowList/ToolBlockList are
// copied onto the DetectRequest so the detector can enforce them.
//
// Each goroutine sends its result through a buffered channel, so the main
// goroutine can safely read completed results without racing against
// in-flight writes. When the deadline fires, we stop reading and return
// whatever has been collected. Late-finishing goroutines send into the
// buffered channel (which has capacity for all detectors) and are never
// read — the channel is GC'd once all references are gone.
func (e *SentryEngine) Evaluate(ctx context.Context, req *DetectRequest, policy *PolicyConfig) ([]*guardv1.DetectorResult, time.Duration) {
	start := time.Now()

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Filter detectors based on policy and build per-detector requests.
	type detectorJob struct {
		detector Detector
		req      *DetectRequest
	}
	jobs := make([]detectorJob, 0, len(e.detectors))
	for _, det := range e.detectors {
		dp := policy.GetDetectorPolicy(det.Name())
		if !dp.IsEnabled() {
			continue
		}

		// For tool_abuse, set per-project allow/block lists from policy.
		detReq := req
		if det.Name() == "tool_abuse" && (len(dp.AllowedTools) > 0 || len(dp.BlockedTools) > 0) {
			detReq = &DetectRequest{
				Payload:       req.Payload,
				Action:        req.Action,
				ToolCall:      req.ToolCall,
				ToolAllowList: dp.AllowedTools,
				ToolBlockList: dp.BlockedTools,
			}
		}

		jobs = append(jobs, detectorJob{detector: det, req: detReq})
	}

	ch := make(chan detectorOutput, len(jobs))

	for _, job := range jobs {
		go func(d Detector, r *DetectRequest) {
			result, err := d.Detect(ctx, r)
			ch <- detectorOutput{
				name:     d.Name(),
				category: d.Category(),
				result:   result,
				err:      err,
			}
		}(job.detector, job.req)
	}

	collected := make([]detectorOutput, 0, len(jobs))
	remaining := len(jobs)
	for remaining > 0 {
		select {
		case out := <-ch:
			collected = append(collected, out)
			remaining--
		case <-ctx.Done():
			e.logger.Warn("detector timeout exceeded, returning partial results",
				zap.Duration("timeout", e.timeout),
			)
			remaining = 0
		}
	}

	results := make([]*guardv1.DetectorResult, 0, len(collected))
	for _, out := range collected {
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
