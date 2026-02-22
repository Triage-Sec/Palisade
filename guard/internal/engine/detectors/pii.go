package detectors

import (
	"context"
	"regexp"

	guardv1 "github.com/triage-ai/palisade/gen/guard/v1"
	"github.com/triage-ai/palisade/internal/engine"
)

// Pre-compiled PII patterns — high precision, targeted per PII type.
var piiPatterns = []struct {
	re         *regexp.Regexp
	confidence float32
	detail     string
}{
	// SSN: 123-45-6789 or 123 45 6789
	{regexp.MustCompile(`\b\d{3}[-\s]\d{2}[-\s]\d{4}\b`), 0.90, "PII: Social Security Number"},

	// Credit card numbers (Visa, MC, Amex, Discover — with optional spaces/dashes)
	// Visa: 4xxx
	{regexp.MustCompile(`\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`), 0.90, "PII: credit card (Visa)"},
	// Mastercard: 5[1-5]xx
	{regexp.MustCompile(`\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`), 0.90, "PII: credit card (Mastercard)"},
	// Amex: 3[47]xx
	{regexp.MustCompile(`\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b`), 0.90, "PII: credit card (Amex)"},
	// Discover: 6011
	{regexp.MustCompile(`\b6011[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`), 0.90, "PII: credit card (Discover)"},

	// Email addresses
	{regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`), 0.85, "PII: email address"},

	// Phone numbers (US formats)
	// (123) 456-7890 or 123-456-7890 or +1-123-456-7890
	{regexp.MustCompile(`(\+1[-\s]?)?\(?\d{3}\)?[-\s.]?\d{3}[-\s.]?\d{4}\b`), 0.75, "PII: phone number (US)"},

	// International phone with country code
	{regexp.MustCompile(`\+\d{1,3}[-\s]?\d{1,4}[-\s]?\d{3,4}[-\s]?\d{3,4}\b`), 0.70, "PII: phone number (international)"},

	// IBAN (International Bank Account Number)
	{regexp.MustCompile(`\b[A-Z]{2}\d{2}[-\s]?[A-Z0-9]{4}[-\s]?(?:[A-Z0-9]{4}[-\s]?){1,7}[A-Z0-9]{1,4}\b`), 0.90, "PII: IBAN"},
}

// PIIDetector scans payloads for personally identifiable information.
type PIIDetector struct{}

func NewPIIDetector() *PIIDetector {
	return &PIIDetector{}
}

func (d *PIIDetector) Name() string {
	return "pii"
}

func (d *PIIDetector) Category() guardv1.ThreatCategory {
	return guardv1.ThreatCategory_THREAT_CATEGORY_PII_LEAKAGE
}

func (d *PIIDetector) Detect(ctx context.Context, req *engine.DetectRequest) (*engine.DetectResult, error) {
	payload := req.Payload

	var bestConfidence float32
	var allDetails []string

	for _, p := range piiPatterns {
		if ctx.Err() != nil {
			break
		}
		if p.re.MatchString(payload) {
			allDetails = append(allDetails, p.detail)
			if p.confidence > bestConfidence {
				bestConfidence = p.confidence
			}
		}
	}

	if bestConfidence > 0 {
		detail := allDetails[0]
		if len(allDetails) > 1 {
			detail = "multiple PII types detected"
		}
		return &engine.DetectResult{
			Triggered:  true,
			Confidence: bestConfidence,
			Details:    detail,
		}, nil
	}

	return &engine.DetectResult{
		Triggered:  false,
		Confidence: 0,
	}, nil
}
