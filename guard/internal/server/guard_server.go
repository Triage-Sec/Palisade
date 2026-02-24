package server

import (
	"context"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/google/uuid"
	guardv1 "github.com/triage-ai/palisade/gen/guard/v1"
	"github.com/triage-ai/palisade/internal/engine"
	"github.com/triage-ai/palisade/internal/storage"
	"go.uber.org/zap"
)

// GuardServer implements the GuardService gRPC service.
type GuardServer struct {
	guardv1.UnimplementedGuardServiceServer
	engine *engine.SentryEngine
	writer storage.EventWriter
	aggCfg engine.AggregatorConfig
	logger *zap.Logger
}

// NewGuardServer creates a new GuardServer with the given dependencies.
func NewGuardServer(
	eng *engine.SentryEngine,
	writer storage.EventWriter,
	aggCfg engine.AggregatorConfig,
	logger *zap.Logger,
) *GuardServer {
	return &GuardServer{
		engine: eng,
		writer: writer,
		aggCfg: aggCfg,
		logger: logger,
	}
}

// Check implements the GuardService.Check RPC.
// Guard is a pure stateless compute engine: the caller sends the project context
// (mode, policy) inline. No authentication is performed here.
func (s *GuardServer) Check(ctx context.Context, req *guardv1.CheckRequest) (*guardv1.CheckResponse, error) {
	start := time.Now()

	// 1. Extract project context from request (caller is responsible for auth)
	projectID := req.ProjectId
	mode := protoModeToString(req.Mode)
	policy := protoToEnginePolicy(req.Policy)

	// 2. Build detect request
	detectReq := &engine.DetectRequest{
		Payload:  req.Payload,
		Action:   req.Action,
		ToolCall: req.ToolCall,
	}

	// 3. Fan-out to all detectors (policy filters disabled detectors + sets tool lists)
	detectorResults, _ := s.engine.Evaluate(ctx, detectReq, policy)

	// 4. Aggregate results into verdict (per-detector thresholds from policy)
	aggResult := engine.AggregateWithPolicy(detectorResults, s.aggCfg, policy)
	realVerdict := aggResult.Verdict

	// 5. Shadow mode: log the real verdict to ClickHouse but return ALLOW to the client.
	responseVerdict := realVerdict
	isShadow := false
	if mode == "shadow" && realVerdict != guardv1.Verdict_VERDICT_ALLOW {
		isShadow = true
		responseVerdict = guardv1.Verdict_VERDICT_ALLOW
	}

	requestID := uuid.New().String()
	latencyMs := float32(float64(time.Since(start)) / float64(time.Millisecond))

	// 6. Fire-and-forget: write security event with the REAL verdict so the
	//    dashboard query "countIf(verdict = 'block') as would_block" works.
	s.writeEvent(req, projectID, requestID, realVerdict, isShadow, aggResult.Reason, detectorResults, latencyMs)

	// 7. Return response with the (possibly overridden) verdict to the client.
	return &guardv1.CheckResponse{
		Verdict:   responseVerdict,
		Detectors: detectorResults,
		LatencyMs: latencyMs,
		RequestId: requestID,
		IsShadow:  isShadow,
		Reason:    aggResult.Reason,
	}, nil
}

// CheckBatch is not implemented yet.
func (s *GuardServer) CheckBatch(_ *guardv1.CheckBatchRequest, _ guardv1.GuardService_CheckBatchServer) error {
	return nil
}

// protoToEnginePolicy converts the proto PolicyConfigProto to the internal engine.PolicyConfig.
// Returns nil if the proto policy is nil or empty (server defaults apply).
func protoToEnginePolicy(p *guardv1.PolicyConfigProto) *engine.PolicyConfig {
	if p == nil || len(p.Detectors) == 0 {
		return nil
	}
	detectors := make(map[string]engine.DetectorPolicy, len(p.Detectors))
	for name, dp := range p.Detectors {
		edp := engine.DetectorPolicy{
			AllowedTools: dp.AllowedTools,
			BlockedTools: dp.BlockedTools,
		}
		if dp.Enabled != nil {
			edp.Enabled = dp.Enabled
		}
		if dp.BlockThreshold != nil {
			v := *dp.BlockThreshold
			edp.BlockThreshold = &v
		}
		if dp.FlagThreshold != nil {
			v := *dp.FlagThreshold
			edp.FlagThreshold = &v
		}
		detectors[name] = edp
	}
	return &engine.PolicyConfig{Detectors: detectors}
}

// protoModeToString converts the proto ProjectMode enum to the string used internally.
func protoModeToString(m guardv1.ProjectMode) string {
	if m == guardv1.ProjectMode_PROJECT_MODE_SHADOW {
		return "shadow"
	}
	return "enforce"
}

func (s *GuardServer) writeEvent(
	req *guardv1.CheckRequest,
	projectID, requestID string,
	verdict guardv1.Verdict,
	isShadow bool,
	reason string,
	detectors []*guardv1.DetectorResult,
	latencyMs float32,
) {
	// Build parallel arrays for detector results
	names := make([]string, len(detectors))
	triggered := make([]bool, len(detectors))
	confidences := make([]float32, len(detectors))
	categories := make([]string, len(detectors))
	details := make([]string, len(detectors))
	for i, d := range detectors {
		names[i] = d.Detector
		triggered[i] = d.Triggered
		confidences[i] = d.Confidence
		categories[i] = d.Category.String()
		details[i] = d.Details
	}

	// Extract tool call info
	var toolName, toolArgs string
	if req.ToolCall != nil {
		toolName = req.ToolCall.FunctionName
		toolArgs = req.ToolCall.ArgumentsJson
	}

	// Extract identity
	var userID, sessionID, tenantID string
	if req.Identity != nil {
		userID = req.Identity.UserId
		sessionID = req.Identity.SessionId
		tenantID = req.Identity.TenantId
	}

	// SHA256 produces 32 bytes — store as raw bytes for FixedString(32)
	hashBytes := sha256.Sum256([]byte(req.Payload))
	payloadHash := string(hashBytes[:])

	event := &storage.SecurityEvent{
		RequestID:           requestID,
		ProjectID:           projectID,
		Timestamp:           time.Now(),
		Action:              actionToClickHouse(req.Action),
		PayloadPreview:      storage.TruncatePayload(req.Payload, storage.PayloadPreviewLength),
		PayloadHash:         payloadHash,
		PayloadSize:         uint32(len(req.Payload)),
		Verdict:             verdictToClickHouse(verdict),
		IsShadow:            isShadow,
		Reason:              reason,
		DetectorNames:       names,
		DetectorTriggered:   triggered,
		DetectorConfidences: confidences,
		DetectorCategories:  categories,
		DetectorDetails:     details,
		UserID:              userID,
		SessionID:           sessionID,
		TenantID:            tenantID,
		ClientTraceID:       req.ClientTraceId,
		ToolName:            toolName,
		ToolArguments:       toolArgs,
		Metadata:            req.Metadata,
		LatencyMs:           latencyMs,
		Source:              "sdk", // Gateway will set this via metadata later
	}

	s.writer.Write(event)
}

// actionToClickHouse converts a protobuf ActionType enum (e.g. "ACTION_TYPE_LLM_INPUT")
// to the lowercase ClickHouse Enum8 value (e.g. "llm_input").
func actionToClickHouse(a guardv1.ActionType) string {
	// Strip "ACTION_TYPE_" prefix and lowercase
	s := a.String()
	s = strings.TrimPrefix(s, "ACTION_TYPE_")
	return strings.ToLower(s)
}

// verdictToClickHouse converts a protobuf Verdict enum (e.g. "VERDICT_BLOCK")
// to the lowercase ClickHouse Enum8 value (e.g. "block").
func verdictToClickHouse(v guardv1.Verdict) string {
	s := v.String()
	s = strings.TrimPrefix(s, "VERDICT_")
	return strings.ToLower(s)
}
