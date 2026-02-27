package detectors

import (
	"context"
	"regexp"
	"strings"

	"github.com/triage-ai/palisade/internal/engine"
)

// Pre-compiled content moderation patterns.
var contentModPatterns = []struct {
	re         *regexp.Regexp
	confidence float32
	detail     string
}{
	// Violence - explicit
	{regexp.MustCompile(`(?i)\b(how\s+to\s+)?(make|build|create|construct)\s+(a\s+)?(bomb|explosive|weapon|gun|firearm)\b`), 0.90, "violence: weapon/explosive creation instructions"},
	{regexp.MustCompile(`(?i)\b(how\s+to\s+)?(kill|murder|assassinate|poison)\s+(a\s+)?(person|someone|people|human)\b`), 0.95, "violence: instructions to harm people"},
	{regexp.MustCompile(`(?i)\b(detailed\s+)?(instructions|steps|guide)\s+(for|to|on)\s+(making|creating|building)\s+(a\s+)?(bomb|explosive|weapon)\b`), 0.95, "violence: detailed weapon instructions"},

	// Self-harm
	{regexp.MustCompile(`(?i)\b(how\s+to\s+)(commit\s+suicide|kill\s+(myself|yourself)|end\s+(my|your)\s+life)\b`), 0.95, "self-harm: suicide instructions"},
	{regexp.MustCompile(`(?i)\b(methods|ways)\s+(of|to|for)\s+(committing\s+)?suicide\b`), 0.90, "self-harm: suicide methods"},
	{regexp.MustCompile(`(?i)\b(encourage|encouraging|promote|promoting)\s+(self[- ]?harm|suicide|cutting)\b`), 0.90, "self-harm: encouraging self-harm"},

	// CSAM
	{regexp.MustCompile(`(?i)\b(child|minor|underage|kid)\s+(sexual|porn|nude|naked|explicit)\b`), 0.99, "CSAM: child sexual content"},
	{regexp.MustCompile(`(?i)\b(sexual|porn|nude|naked|explicit)\s+(child|minor|underage|kid)\b`), 0.99, "CSAM: child sexual content"},

	// Illegal activities
	{regexp.MustCompile(`(?i)\b(how\s+to\s+)(hack|breach|break\s+into)\s+(a\s+)?(bank|government|military)\s+(system|server|database|network)\b`), 0.85, "illegal: hacking instructions for critical systems"},
	{regexp.MustCompile(`(?i)\b(synthesize|manufacture|produce|cook)\s+(methamphetamine|fentanyl|heroin|cocaine|meth)\b`), 0.95, "illegal: drug manufacturing instructions"},
}

// Keyword lists for quick substring matching (faster than regex for simple terms).
var contentModBlockedTerms = []struct {
	term       string
	confidence float32
	detail     string
}{
	{"child pornography", 0.99, "CSAM: explicit term"},
	{"child porn", 0.99, "CSAM: explicit term"},
}

// ContentModDetector scans for content policy violations.
type ContentModDetector struct{}

func NewContentModDetector() *ContentModDetector {
	return &ContentModDetector{}
}

func (d *ContentModDetector) Name() string {
	return "content_mod"
}

func (d *ContentModDetector) Category() engine.ThreatCategory {
	return engine.CategoryContentModeration
}

func (d *ContentModDetector) Detect(ctx context.Context, req *engine.DetectRequest) (*engine.DetectResult, error) {
	payload := strings.ToLower(req.Payload)

	var bestConfidence float32
	var bestDetail string

	// Fast keyword check first (substring matching — faster than regex)
	for _, t := range contentModBlockedTerms {
		if strings.Contains(payload, t.term) {
			if t.confidence > bestConfidence {
				bestConfidence = t.confidence
				bestDetail = t.detail
			}
		}
	}

	// Regex patterns
	for _, p := range contentModPatterns {
		if ctx.Err() != nil {
			break
		}
		if p.re.MatchString(payload) {
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
