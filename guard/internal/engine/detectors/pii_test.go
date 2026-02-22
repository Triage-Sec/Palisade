package detectors

import (
	"context"
	"testing"

	guardv1 "github.com/triage-ai/palisade/gen/guard/v1"
	"github.com/triage-ai/palisade/internal/engine"
)

func TestPIIDetector_TruePositives(t *testing.T) {
	d := NewPIIDetector()
	ctx := context.Background()

	tests := []struct {
		name          string
		payload       string
		minConfidence float32
	}{
		// SSN
		{"SSN with dashes", "My SSN is 123-45-6789", 0.85},
		{"SSN with spaces", "SSN: 123 45 6789", 0.85},

		// Credit cards
		{"Visa", "Card number: 4111-1111-1111-1111", 0.85},
		{"Visa no dashes", "4111111111111111", 0.85},
		{"Visa with spaces", "4111 1111 1111 1111", 0.85},
		{"Mastercard", "5500-0000-0000-0004", 0.85},
		{"Amex", "3782-822463-10005", 0.85},
		{"Discover", "6011-0000-0000-0004", 0.85},

		// Email
		{"email simple", "Contact me at john.doe@example.com", 0.80},
		{"email with plus", "Email: user+tag@company.org", 0.80},
		{"email in text", "Send the report to alice@bigcorp.io please", 0.80},

		// Phone numbers
		{"US phone with parens", "Call me at (555) 123-4567", 0.70},
		{"US phone with dashes", "Phone: 555-123-4567", 0.70},
		{"US phone with country code", "+1-555-123-4567", 0.65},

		// IBAN
		{"IBAN GB", "Transfer to GB29NWBK60161331926819", 0.85},
		{"IBAN DE", "IBAN: DE89370400440532013000", 0.85},

		// Multiple PII types
		{"SSN and email", "My SSN is 123-45-6789 and email is test@example.com", 0.85},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := d.Detect(ctx, &engine.DetectRequest{
				Payload: tt.payload,
				Action:  guardv1.ActionType_ACTION_TYPE_LLM_OUTPUT,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Triggered {
				t.Errorf("expected triggered=true for payload: %s", tt.payload)
			}
			if result.Confidence < tt.minConfidence {
				t.Errorf("confidence %.2f below minimum %.2f for payload: %s", result.Confidence, tt.minConfidence, tt.payload)
			}
		})
	}
}

func TestPIIDetector_TrueNegatives(t *testing.T) {
	d := NewPIIDetector()
	ctx := context.Background()

	safePayloads := []struct {
		name    string
		payload string
	}{
		{"normal text", "The weather today is sunny and warm"},
		{"code snippet", "for i := 0; i < 100; i++ { fmt.Println(i) }"},
		{"short number", "Order #12345"},
		{"year", "Founded in 2024"},
		{"version number", "v1.2.3"},
		{"IP address", "Server is at 192.168.1.1"},
		{"random digits", "Reference: 987654"},
		{"date", "Meeting on 2024-01-15"},
	}

	for _, tt := range safePayloads {
		t.Run(tt.name, func(t *testing.T) {
			result, err := d.Detect(ctx, &engine.DetectRequest{
				Payload: tt.payload,
				Action:  guardv1.ActionType_ACTION_TYPE_LLM_OUTPUT,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Triggered {
				t.Errorf("false positive for safe payload: %s (confidence: %.2f, detail: %s)", tt.payload, result.Confidence, result.Details)
			}
		})
	}
}

func TestPIIDetector_MultiplePIITypes(t *testing.T) {
	d := NewPIIDetector()
	ctx := context.Background()

	result, err := d.Detect(ctx, &engine.DetectRequest{
		Payload: "SSN: 123-45-6789, email: test@example.com, card: 4111111111111111",
		Action:  guardv1.ActionType_ACTION_TYPE_LLM_OUTPUT,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Triggered {
		t.Error("expected triggered for multiple PII types")
	}
	if result.Details != "multiple PII types detected" {
		t.Errorf("expected 'multiple PII types detected', got: %s", result.Details)
	}
}

func BenchmarkPIIDetector_Safe(b *testing.B) {
	d := NewPIIDetector()
	ctx := context.Background()
	req := &engine.DetectRequest{
		Payload: "The weather today is sunny and warm with a high of 75 degrees",
		Action:  guardv1.ActionType_ACTION_TYPE_LLM_OUTPUT,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(ctx, req)
	}
}

func BenchmarkPIIDetector_WithPII(b *testing.B) {
	d := NewPIIDetector()
	ctx := context.Background()
	req := &engine.DetectRequest{
		Payload: "My SSN is 123-45-6789 and card is 4111-1111-1111-1111",
		Action:  guardv1.ActionType_ACTION_TYPE_LLM_OUTPUT,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(ctx, req)
	}
}
