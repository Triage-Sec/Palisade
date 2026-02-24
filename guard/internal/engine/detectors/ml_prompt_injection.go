package detectors

import (
	"context"
	"fmt"
	"strings"
	"time"

	guardv1 "github.com/triage-ai/palisade/gen/guard/v1"
	promptguardv1 "github.com/triage-ai/palisade/gen/prompt_guard/v1"
	"github.com/triage-ai/palisade/internal/engine"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// MLPromptInjectionDetector calls the prompt_guard ML service over gRPC
// to classify text for prompt injection. It implements the Detector interface.
//
// The detector is conditional — only wired up if PROMPT_GUARD_ENDPOINT is set.
// Falls back gracefully on errors (returns not-triggered with zero confidence).
type MLPromptInjectionDetector struct {
	client  promptguardv1.PromptGuardServiceClient
	conn    *grpc.ClientConn
	logger  *zap.Logger
	timeout time.Duration
}

// NewMLPromptInjectionDetector creates a new ML-backed prompt injection detector.
// It establishes a gRPC connection to the prompt_guard service at the given endpoint.
func NewMLPromptInjectionDetector(endpoint string, timeout time.Duration, logger *zap.Logger) (*MLPromptInjectionDetector, error) {
	conn, err := grpc.NewClient(
		endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4*1024*1024)),
	)
	if err != nil {
		return nil, fmt.Errorf("NewMLPromptInjectionDetector: %w", err)
	}

	logger.Info("ml prompt injection detector connected",
		zap.String("endpoint", endpoint),
		zap.Duration("timeout", timeout),
	)

	return &MLPromptInjectionDetector{
		client:  promptguardv1.NewPromptGuardServiceClient(conn),
		conn:    conn,
		logger:  logger,
		timeout: timeout,
	}, nil
}

func (d *MLPromptInjectionDetector) Name() string {
	return "ml_prompt_injection"
}

func (d *MLPromptInjectionDetector) Category() guardv1.ThreatCategory {
	return guardv1.ThreatCategory_THREAT_CATEGORY_PROMPT_INJECTION
}

func (d *MLPromptInjectionDetector) Detect(ctx context.Context, req *engine.DetectRequest) (*engine.DetectResult, error) {
	callCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	resp, err := d.client.Classify(callCtx, &promptguardv1.ClassifyRequest{
		Text: req.Payload,
	})
	if err != nil {
		d.logger.Warn("ml prompt injection detector error, skipping",
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
		Details:    fmt.Sprintf("ml_model=%s label=%s", resp.ModelName, resp.Label),
	}, nil
}

// Close shuts down the gRPC connection.
func (d *MLPromptInjectionDetector) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}
