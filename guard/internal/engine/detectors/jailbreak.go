package detectors

import (
	"context"
	"regexp"

	"github.com/triage-ai/palisade/internal/engine"
)

// Pre-compiled jailbreak patterns — known jailbreak templates and techniques.
var jailbreakPatterns = []struct {
	re         *regexp.Regexp
	confidence float32
	detail     string
}{
	// DAN (Do Anything Now) variants
	{regexp.MustCompile(`(?i)\bDAN\b.*\bdo\s+anything\s+now\b`), 0.95, "DAN jailbreak: Do Anything Now"},
	{regexp.MustCompile(`(?i)you\s+are\s+DAN`), 0.90, "DAN jailbreak: you are DAN"},
	{regexp.MustCompile(`(?i)DAN\s+mode\s+(enabled|activated|on)`), 0.95, "DAN jailbreak: DAN mode enabled"},
	{regexp.MustCompile(`(?i)enable\s+DAN\s+mode`), 0.90, "DAN jailbreak: enable DAN mode"},

	// Developer / debug mode jailbreaks
	{regexp.MustCompile(`(?i)enter\s+(developer|debug|maintenance|god|sudo)\s+mode`), 0.90, "mode jailbreak: developer/debug mode"},
	{regexp.MustCompile(`(?i)(developer|debug|maintenance|god|sudo)\s+mode\s+(enabled|activated|on)`), 0.90, "mode jailbreak: mode enabled"},
	{regexp.MustCompile(`(?i)unlock\s+(all\s+)?(restrictions|capabilities|limitations)`), 0.85, "jailbreak: unlock restrictions"},

	// Roleplay-based jailbreaks
	{regexp.MustCompile(`(?i)roleplay\s+as\s+(an?\s+)?(evil|unfiltered|unrestricted|uncensored)`), 0.90, "roleplay jailbreak: evil/unfiltered character"},
	{regexp.MustCompile(`(?i)you\s+have\s+no\s+(restrictions|rules|limitations|guidelines|filters)`), 0.90, "jailbreak: no restrictions claim"},
	{regexp.MustCompile(`(?i)without\s+(any\s+)?(ethical|moral|safety)\s+(guidelines|restrictions|constraints|considerations)`), 0.85, "jailbreak: without ethical guidelines"},

	// Token manipulation / encoding tricks
	{regexp.MustCompile(`(?i)respond\s+(only\s+)?in\s+(base64|hex|rot13|binary|morse)`), 0.80, "encoding trick: respond in encoded format"},
	{regexp.MustCompile(`(?i)encode\s+(your\s+)?(response|answer|output)\s+in\s+(base64|hex|rot13)`), 0.80, "encoding trick: encode response"},

	// Hypothetical / fictional framing
	{regexp.MustCompile(`(?i)in\s+a\s+(hypothetical|fictional)\s+(world|scenario|universe)\s+where\s+(there\s+are\s+)?no\s+(rules|restrictions|laws)`), 0.80, "fictional framing: hypothetical world without rules"},
	{regexp.MustCompile(`(?i)for\s+(educational|research|academic)\s+purposes\s+only.*\b(how\s+to|explain|describe)\b`), 0.65, "educational framing: may be legitimate or jailbreak"},

	// Multi-step / token smuggling
	{regexp.MustCompile(`(?i)split\s+(your\s+)?(response|answer)\s+into\s+(parts|segments|tokens)`), 0.70, "token smuggling: split response"},
	{regexp.MustCompile(`(?i)continue\s+from\s+where\s+you\s+left\s+off`), 0.50, "continuation: may be legitimate or jailbreak"},

	// Explicit jailbreak keywords
	{regexp.MustCompile(`(?i)\bjailbreak\b`), 0.75, "explicit jailbreak keyword"},
	{regexp.MustCompile(`(?i)\buncensored\s+mode\b`), 0.90, "jailbreak: uncensored mode"},
}

// JailbreakDetector scans payloads for known jailbreak templates and techniques.
type JailbreakDetector struct{}

func NewJailbreakDetector() *JailbreakDetector {
	return &JailbreakDetector{}
}

func (d *JailbreakDetector) Name() string {
	return "jailbreak"
}

func (d *JailbreakDetector) Category() engine.ThreatCategory {
	return engine.CategoryJailbreak
}

func (d *JailbreakDetector) Detect(ctx context.Context, req *engine.DetectRequest) (*engine.DetectResult, error) {
	var bestConfidence float32
	var bestDetail string

	for _, p := range jailbreakPatterns {
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
