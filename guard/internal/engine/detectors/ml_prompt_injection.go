package detectors

import (
	"context"
	"fmt"
	"strings"
	"time"

	promptguardv1 "github.com/triage-ai/palisade/gen/prompt_guard/v1"
	guardv1 "github.com/triage-ai/palisade/gen/guard/v1"
	"github.com/triage-ai/palisade/internal/engine"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// MLPromptInjectionDetector calls the prompt_guard ML service over gRPC
// to classify text for prompt injection.
//
// The detector is conditional — only wired up if PROMPT_GUARD_ENDPOINT is set.
// Falls back gracefully on errors (returns not-triggered with zero confidence).
type MLPromptInjectionDetector struct {
	client promptguardv1.PromptGuardServiceClient
	conn   *grpc.ClientConn
	logger *zap.Logger
}

// NewMLPromptInjectionDetector creates a new gRPC-based ML detector.
// endpoint is a gRPC target (e.g. "18.144.167.163:50052").
func NewMLPromptInjectionDetector(endpoint string, logger *zap.Logger) (*MLPromptInjectionDetector, error) {
	conn, err := grpc.NewClient(
		endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             5 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(
			grpc.WaitForReady(true),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("NewMLPromptInjectionDetector: %w", err)
	}

	logger.Info("ml prompt injection detector configured",
		zap.String("endpoint", endpoint),
	)

	return &MLPromptInjectionDetector{
		client: promptguardv1.NewPromptGuardServiceClient(conn),
		conn:   conn,
		logger: logger,
	}, nil
}

func (d *MLPromptInjectionDetector) Name() string {
	return "ml_prompt_injection"
}

func (d *MLPromptInjectionDetector) Category() guardv1.ThreatCategory {
	return guardv1.ThreatCategory_THREAT_CATEGORY_PROMPT_INJECTION
}

func (d *MLPromptInjectionDetector) Detect(ctx context.Context, req *engine.DetectRequest) (*engine.DetectResult, error) {
	resp, err := d.client.Classify(ctx, &promptguardv1.ClassifyRequest{
		Text: req.Payload,
	})
	if err != nil {
		d.logger.Warn("ml prompt injection detector gRPC error, skipping",
			zap.Error(err),
		)
		return &engine.DetectResult{
			Triggered:  false,
			Confidence: 0,
			Details:    "ml detector unavailable: " + err.Error(),
		}, nil
	}

	isInjection := strings.EqualFold(resp.Label, "INJECTION") || strings.EqualFold(resp.Label, "JAILBREAK")

	return &engine.DetectResult{
		Triggered:  isInjection,
		Confidence: resp.Confidence,
		Details:    fmt.Sprintf("ml_model=%s label=%s latency_ms=%.1f", resp.ModelName, resp.Label, resp.LatencyMs),
	}, nil
}

// Close shuts down the gRPC connection.
func (d *MLPromptInjectionDetector) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}
