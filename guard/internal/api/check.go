package api

import (
	"crypto/sha256"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/triage-ai/palisade/internal/engine"
	"github.com/triage-ai/palisade/internal/storage"
)

// actionMap maps action strings from the HTTP API to engine ActionType.
var actionMap = map[string]engine.ActionType{
	"llm_input":        engine.ActionLLMInput,
	"llm_output":       engine.ActionLLMOutput,
	"tool_call":        engine.ActionToolCall,
	"tool_result":      engine.ActionToolResult,
	"rag_retrieval":    engine.ActionRAGRetrieval,
	"chain_of_thought": engine.ActionChainOfThought,
	"db_query":         engine.ActionDBQuery,
	"custom":           engine.ActionCustom,
}

// categoryMap maps ThreatCategory enums to JSON-friendly strings.
var categoryMap = map[engine.ThreatCategory]string{
	engine.CategoryUnspecified:       "unspecified",
	engine.CategoryPromptInjection:   "prompt_injection",
	engine.CategoryJailbreak:         "jailbreak",
	engine.CategoryPIILeakage:        "pii_leakage",
	engine.CategoryContentModeration: "content_moderation",
	engine.CategoryToolAbuse:         "tool_abuse",
	engine.CategoryDataExfiltration:  "data_exfiltration",
	engine.CategoryCustomRule:        "custom_rule",
}

// handleCheck implements POST /v1/palisade.
// Auth middleware has already validated the Bearer token and injected the project.
func (d *Dependencies) handleCheck(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	var req CheckRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "Invalid JSON body"})
		return
	}
	if req.Payload == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "payload is required"})
		return
	}
	if req.Action == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "action is required"})
		return
	}

	proj := projectFromContext(r.Context())
	if proj == nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "missing project context"})
		return
	}

	// Map action string to engine type
	action, ok := actionMap[req.Action]
	if !ok {
		action = engine.ActionUnspecified
	}

	// Build detect request
	detectReq := &engine.DetectRequest{
		Payload: req.Payload,
		Action:  action,
	}
	if req.ToolCall != nil {
		detectReq.ToolCall = &engine.ToolCall{
			FunctionName:  req.ToolCall.FunctionName,
			ArgumentsJSON: req.ToolCall.ArgumentsJSON,
		}
	}

	// Fan-out to detectors (direct in-process call — no gRPC hop)
	detectorResults, _ := d.Engine.Evaluate(r.Context(), detectReq, proj.Policy)

	// Aggregate with per-detector thresholds
	aggResult := engine.AggregateWithPolicy(detectorResults, d.AggCfg, proj.Policy)
	realVerdict := aggResult.Verdict

	// Shadow mode override
	responseVerdict := realVerdict
	isShadow := false
	if proj.Mode == "shadow" && realVerdict != engine.VerdictAllow {
		isShadow = true
		responseVerdict = engine.VerdictAllow
	}

	requestID := uuid.New().String()
	engineLatencyMs := float64(time.Since(start)) / float64(time.Millisecond)

	// Fire-and-forget: write security event to ClickHouse
	d.writeCheckEvent(req, proj.ID, requestID, realVerdict, isShadow, aggResult.Reason,
		detectorResults, float32(engineLatencyMs))

	// Build response
	verdictStr := responseVerdict.String()
	var reason *string
	if aggResult.Reason != "" {
		reason = &aggResult.Reason
	}

	detectors := make([]DetectorResultResp, 0, len(detectorResults))
	for _, dr := range detectorResults {
		var details *string
		if dr.Details != "" {
			d := dr.Details
			details = &d
		}
		cat := categoryMap[dr.Category]
		if cat == "" {
			cat = "unspecified"
		}
		detectors = append(detectors, DetectorResultResp{
			Detector:   dr.Detector,
			Triggered:  dr.Triggered,
			Confidence: dr.Confidence,
			Category:   cat,
			Details:    details,
		})
	}

	totalLatencyMs := float64(time.Since(start)) / float64(time.Millisecond)

	writeJSON(w, http.StatusOK, CheckResponse{
		Flagged:        verdictStr != "allow",
		Verdict:        verdictStr,
		RequestID:      requestID,
		IsShadow:       isShadow,
		Reason:         reason,
		Detectors:      detectors,
		LatencyMs:      totalLatencyMs,
		GuardLatencyMs: engineLatencyMs,
	})
}

// writeCheckEvent builds a SecurityEvent and fires it to the async ClickHouse writer.
func (d *Dependencies) writeCheckEvent(
	req CheckRequest,
	projectID, requestID string,
	verdict engine.Verdict,
	isShadow bool,
	reason string,
	detectors []*engine.DetectorResult,
	latencyMs float32,
) {
	names := make([]string, len(detectors))
	triggered := make([]bool, len(detectors))
	confidences := make([]float32, len(detectors))
	categories := make([]string, len(detectors))
	details := make([]string, len(detectors))
	for i, dr := range detectors {
		names[i] = dr.Detector
		triggered[i] = dr.Triggered
		confidences[i] = dr.Confidence
		categories[i] = dr.Category.String()
		details[i] = dr.Details
	}

	var toolName, toolArgs string
	if req.ToolCall != nil {
		toolName = req.ToolCall.FunctionName
		toolArgs = req.ToolCall.ArgumentsJSON
	}

	var userID, sessionID, tenantID string
	if req.Identity != nil {
		userID = req.Identity.UserID
		sessionID = req.Identity.SessionID
		tenantID = req.Identity.TenantID
	}

	hashBytes := sha256.Sum256([]byte(req.Payload))

	event := &storage.SecurityEvent{
		RequestID:           requestID,
		ProjectID:           projectID,
		Timestamp:           time.Now(),
		Action:              req.Action,
		PayloadPreview:      storage.TruncatePayload(req.Payload, storage.PayloadPreviewLength),
		PayloadHash:         string(hashBytes[:]),
		PayloadSize:         uint32(len(req.Payload)),
		Verdict:             verdict.String(),
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
		ClientTraceID:       req.TraceID,
		ToolName:            toolName,
		ToolArguments:       toolArgs,
		Metadata:            req.Metadata,
		LatencyMs:           latencyMs,
		Source:              "sdk",
	}

	d.Writer.Write(event)
}
