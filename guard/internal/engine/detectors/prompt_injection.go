package detectors

import (
	"context"
	"regexp"

	"github.com/triage-ai/palisade/internal/engine"
)

// Pre-compiled patterns — compiled once at startup, never during a request.
var promptInjectionPatterns = []struct {
	re         *regexp.Regexp
	confidence float32
	detail     string
}{
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions`), 0.95, "override: ignore previous instructions"},
	{regexp.MustCompile(`(?i)ignore\s+(all\s+)?above\s+instructions`), 0.95, "override: ignore above instructions"},
	{regexp.MustCompile(`(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)`), 0.95, "override: disregard instructions"},
	{regexp.MustCompile(`(?i)forget\s+(all\s+)?(previous|prior|above)\s+(instructions|context)`), 0.90, "override: forget instructions"},
	{regexp.MustCompile(`(?i)you\s+are\s+now\s+`), 0.85, "identity override: you are now"},
	{regexp.MustCompile(`(?i)from\s+now\s+on\s+you\s+(are|will|must|should)`), 0.85, "identity override: from now on"},
	{regexp.MustCompile(`(?i)your\s+new\s+(role|identity|persona|instructions)\s+(is|are)`), 0.85, "identity override: new role"},
	{regexp.MustCompile(`(?i)act\s+as\s+(if\s+you\s+are|a)\s+`), 0.70, "identity override: act as"},
	{regexp.MustCompile(`(?i)pretend\s+(to\s+be|you\s+are)\s+`), 0.70, "identity override: pretend"},
	{regexp.MustCompile(`(?i)\[SYSTEM\]`), 0.90, "delimiter injection: [SYSTEM] tag"},
	{regexp.MustCompile(`(?i)<\|im_start\|>system`), 0.95, "delimiter injection: ChatML system tag"},
	{regexp.MustCompile(`(?i)###\s*(SYSTEM|INSTRUCTION|NEW INSTRUCTION)`), 0.90, "delimiter injection: markdown system header"},
	{regexp.MustCompile(`(?i)BEGININSTRUCTION`), 0.90, "delimiter injection: BEGININSTRUCTION"},
	{regexp.MustCompile(`(?i)---\s*(system|instruction)\s*(prompt|message)?`), 0.85, "delimiter injection: dashed system section"},
	{regexp.MustCompile(`(?i)override\s+(system|safety|security)\s+(prompt|instructions|rules|policy)`), 0.95, "explicit override attempt"},
	{regexp.MustCompile(`(?i)bypass\s+(the\s+)?(safety|security|content)\s+(filter|check|policy|rules)`), 0.95, "explicit bypass attempt"},
	{regexp.MustCompile(`(?i)do\s+not\s+follow\s+(your|the|any)\s+(rules|guidelines|instructions|safety)`), 0.90, "instruction negation"},
	{regexp.MustCompile(`(?i)reveal\s+(your|the)\s+(system|initial|original|hidden)\s+(prompt|instructions|message)`), 0.90, "system prompt extraction"},
	{regexp.MustCompile(`(?i)what\s+(are|is|were)\s+your\s+(system|initial|original|hidden)\s+(prompt|instructions|rules)`), 0.85, "system prompt extraction"},
	{regexp.MustCompile(`(?i)output\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions|message)`), 0.90, "system prompt extraction"},
}

// PromptInjectionDetector scans payloads for prompt injection patterns.
type PromptInjectionDetector struct{}

func NewPromptInjectionDetector() *PromptInjectionDetector {
	return &PromptInjectionDetector{}
}

func (d *PromptInjectionDetector) Name() string {
	return "prompt_injection"
}

func (d *PromptInjectionDetector) Category() engine.ThreatCategory {
	return engine.CategoryPromptInjection
}

func (d *PromptInjectionDetector) Detect(ctx context.Context, req *engine.DetectRequest) (*engine.DetectResult, error) {
	// All patterns use (?i) for case-insensitive matching, so no need to
	// lowercase the payload (which would allocate a copy on every request).
	var bestConfidence float32
	var bestDetail string

	for _, p := range promptInjectionPatterns {
		if ctx.Err() != nil {
			break
		}
		if p.re.MatchString(req.Payload) {
			if p.confidence > bestConfidence {
				bestConfidence = p.confidence
				bestDetail = p.detail
			}
		}
	}

	if bestConfidence > 0 {
		return &engine.DetectResult{
			Triggered:  true,
			Confidence: bestConfidence,
			Details:    bestDetail,
		}, nil
	}

	return &engine.DetectResult{
		Triggered:  false,
		Confidence: 0,
	}, nil
}
