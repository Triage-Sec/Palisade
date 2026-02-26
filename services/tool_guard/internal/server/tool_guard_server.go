package server

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/auth"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
	"github.com/triage-ai/palisade/services/tool_guard/internal/registry"
	"github.com/triage-ai/palisade/services/tool_guard/internal/storage"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ToolGuardServer implements the ToolGuardService gRPC service.
type ToolGuardServer struct {
	toolguardv1.UnimplementedToolGuardServiceServer
	engine   *engine.ToolGuardEngine
	auth     auth.Authenticator
	registry registry.ToolRegistry
	writer   storage.EventWriter
	aggCfg   engine.AggregatorConfig
	logger   *zap.Logger
}

// NewToolGuardServer creates a new ToolGuardServer with the given dependencies.
func NewToolGuardServer(
	eng *engine.ToolGuardEngine,
	authenticator auth.Authenticator,
	reg registry.ToolRegistry,
	writer storage.EventWriter,
	aggCfg engine.AggregatorConfig,
	logger *zap.Logger,
) *ToolGuardServer {
	return &ToolGuardServer{
		engine:   eng,
		auth:     authenticator,
		registry: reg,
		writer:   writer,
		aggCfg:   aggCfg,
		logger:   logger,
	}
}

// Check implements the ToolGuardService.Check RPC.
func (s *ToolGuardServer) Check(ctx context.Context, req *toolguardv1.ToolCheckRequest) (*toolguardv1.ToolCheckResponse, error) {
	start := time.Now()

	// 1. Authenticate
	project, err := s.auth.Authenticate(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
	}

	// 2. Look up tool definition from registry
	var toolDef *registry.ToolDefinition
	if s.registry != nil {
		td, err := s.registry.GetTool(ctx, project.ProjectID, req.ToolName)
		if err != nil {
			s.logger.Warn("tool registry lookup failed",
				zap.String("project_id", project.ProjectID),
				zap.String("tool_name", req.ToolName),
				zap.Error(err),
			)
			// Continue with nil toolDef (unregistered tool path)
		} else {
			toolDef = td
		}
	}

	// 3. Build evaluation request
	evalReq := &engine.EvalRequest{
		ToolName:      req.ToolName,
		ArgumentsJSON: req.ArgumentsJson,
		Trace:         req.Trace,
		UserConfirmed: req.UserConfirmed,
		WorkflowType:  req.WorkflowType,
		ToolDef:       toolDef,
	}

	// 4. Fan-out to all evaluators
	evalResults, _ := s.engine.Evaluate(ctx, evalReq)

	// 5. Aggregate results into verdict
	aggResult := engine.Aggregate(evalResults, s.aggCfg)

	// 6. Collect output restrictions from tool definition
	var outputRestrictions []string
	if toolDef != nil && len(toolDef.InformationFlow.OutputRestrictions) > 0 {
		outputRestrictions = toolDef.InformationFlow.OutputRestrictions
	}

	requestID := uuid.New().String()
	latencyMs := float32(float64(time.Since(start)) / float64(time.Millisecond))

	// 7. Fire-and-forget: write event
	s.writeEvent(req, project.ProjectID, requestID, aggResult, evalResults, latencyMs)

	return &toolguardv1.ToolCheckResponse{
		Verdict:            aggResult.Verdict,
		Evaluations:        evalResults,
		LatencyMs:          latencyMs,
		RequestId:          requestID,
		Reason:             aggResult.Reason,
		OutputRestrictions: outputRestrictions,
	}, nil
}

func (s *ToolGuardServer) writeEvent(
	req *toolguardv1.ToolCheckRequest,
	projectID, requestID string,
	aggResult engine.AggregateResult,
	evals []*toolguardv1.EvalResult,
	latencyMs float32,
) {
	categories := make([]string, len(evals))
	triggered := make([]bool, len(evals))
	confidences := make([]float32, len(evals))
	details := make([]string, len(evals))
	for i, e := range evals {
		categories[i] = e.Category.String()
		triggered[i] = e.Triggered
		confidences[i] = e.Confidence
		details[i] = e.Details
	}

	var userID, sessionID, tenantID string
	if req.Identity != nil {
		userID = req.Identity.UserId
		sessionID = req.Identity.SessionId
		tenantID = req.Identity.TenantId
	}

	event := &storage.ToolCheckEvent{
		RequestID:       requestID,
		ProjectID:       projectID,
		Timestamp:       time.Now(),
		ToolName:        req.ToolName,
		ArgumentsJSON:   req.ArgumentsJson,
		Verdict:         verdictToString(aggResult.Verdict),
		Reason:          aggResult.Reason,
		EvalCategories:  categories,
		EvalTriggered:   triggered,
		EvalConfidences: confidences,
		EvalDetails:     details,
		UserID:          userID,
		SessionID:       sessionID,
		TenantID:        tenantID,
		ClientTraceID:   req.ClientTraceId,
		WorkflowType:    req.WorkflowType,
		UserConfirmed:   req.UserConfirmed,
		TraceLength:     int32(len(req.Trace)),
		Metadata:        req.Metadata,
		LatencyMs:       latencyMs,
		Source:          "sdk",
	}

	s.writer.Write(event)
}

func verdictToString(v toolguardv1.SafetyVerdict) string {
	s := v.String()
	s = strings.TrimPrefix(s, "SAFETY_VERDICT_")
	return strings.ToLower(s)
}
