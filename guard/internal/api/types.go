package api

import (
	"encoding/json"
	"time"
)

// --- POST /v1/palisade request/response ---

// IdentityReq mirrors the Python IdentityRequest Pydantic model.
type IdentityReq struct {
	UserID    string `json:"user_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// ToolCallReq mirrors the Python ToolCallRequest Pydantic model.
type ToolCallReq struct {
	FunctionName  string `json:"function_name"`
	ArgumentsJSON string `json:"arguments_json,omitempty"`
}

// CheckRequest is the JSON body for POST /v1/palisade.
type CheckRequest struct {
	Payload  string            `json:"payload"`
	Action   string            `json:"action"`
	Identity *IdentityReq      `json:"identity,omitempty"`
	ToolCall *ToolCallReq      `json:"tool_call,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	TraceID  string            `json:"trace_id,omitempty"`
}

// DetectorResultResp mirrors the Python DetectorResultResponse.
type DetectorResultResp struct {
	Detector   string  `json:"detector"`
	Triggered  bool    `json:"triggered"`
	Confidence float32 `json:"confidence"`
	Category   string  `json:"category"`
	Details    *string `json:"details"`
}

// CheckResponse mirrors the Python PalisadeCheckResponse.
type CheckResponse struct {
	Flagged        bool                 `json:"flagged"`
	Verdict        string               `json:"verdict"`
	RequestID      string               `json:"request_id"`
	IsShadow       bool                 `json:"is_shadow"`
	Reason         *string              `json:"reason"`
	Detectors      []DetectorResultResp `json:"detectors"`
	LatencyMs      float64              `json:"latency_ms"`
	GuardLatencyMs float64              `json:"guard_latency_ms"`
}

// --- Project CRUD ---

// CreateProjectReq is the JSON body for POST /api/palisade/projects.
type CreateProjectReq struct {
	Name string `json:"name"`
}

// CreateProjectResp includes the plaintext API key (shown once).
type CreateProjectResp struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	APIKey         string    `json:"api_key"`
	APIKeyPrefix   string    `json:"api_key_prefix"`
	Mode           string    `json:"mode"`
	FailOpen       bool      `json:"fail_open"`
	ChecksPerMonth *int      `json:"checks_per_month"`
	CreatedAt      time.Time `json:"created_at"`
}

// UpdateProjectReq is the JSON body for PATCH /api/palisade/projects/{id}.
type UpdateProjectReq struct {
	Name           *string `json:"name,omitempty"`
	Mode           *string `json:"mode,omitempty"`
	FailOpen       *bool   `json:"fail_open,omitempty"`
	ChecksPerMonth *int    `json:"checks_per_month,omitempty"`
}

// ProjectResp mirrors the Python ProjectResponse (no plaintext key).
type ProjectResp struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	APIKeyPrefix   string    `json:"api_key_prefix"`
	Mode           string    `json:"mode"`
	FailOpen       bool      `json:"fail_open"`
	ChecksPerMonth *int      `json:"checks_per_month"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// RotateKeyResp includes the new plaintext API key (shown once).
type RotateKeyResp struct {
	APIKey       string `json:"api_key"`
	APIKeyPrefix string `json:"api_key_prefix"`
}

// --- Policy CRUD ---

// UpdatePolicyReq is the JSON body for PATCH/PUT policy endpoints.
type UpdatePolicyReq struct {
	DetectorConfig  json.RawMessage `json:"detector_config,omitempty"`
	CustomBlocklist json.RawMessage `json:"custom_blocklist,omitempty"`
}

// PolicyResp mirrors the Python PolicyResponse.
type PolicyResp struct {
	ID              string          `json:"id"`
	ProjectID       string          `json:"project_id"`
	DetectorConfig  json.RawMessage `json:"detector_config"`
	CustomBlocklist json.RawMessage `json:"custom_blocklist"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// --- Security Events ---

// SecurityEventResp mirrors the Python SecurityEventResponse.
type SecurityEventResp struct {
	RequestID     string               `json:"request_id"`
	ProjectID     string               `json:"project_id"`
	Action        string               `json:"action"`
	Verdict       string               `json:"verdict"`
	IsShadow      bool                 `json:"is_shadow"`
	Reason        *string              `json:"reason"`
	Detectors     []DetectorResultResp `json:"detectors"`
	UserID        *string              `json:"user_id"`
	SessionID     *string              `json:"session_id"`
	TenantID      *string              `json:"tenant_id"`
	ClientTraceID *string              `json:"client_trace_id"`
	ToolName      *string              `json:"tool_name"`
	ToolArguments *string              `json:"tool_arguments"`
	LatencyMs     float32              `json:"latency_ms"`
	Source        string               `json:"source"`
	Timestamp     time.Time            `json:"timestamp"`
}

// EventListResp mirrors the Python EventListResponse.
type EventListResp struct {
	Events   []SecurityEventResp `json:"events"`
	Total    int                 `json:"total"`
	Page     int                 `json:"page"`
	PageSize int                 `json:"page_size"`
}

// --- Analytics ---

// AnalyticsResp mirrors the Python AnalyticsResponse.
type AnalyticsResp struct {
	Summary            SummaryStatsResp       `json:"summary"`
	BlocksOverTime     []TimeSeriesBucketResp `json:"blocks_over_time"`
	TopCategories      []CategoryCountResp    `json:"top_categories"`
	ShadowReport       ShadowReportResp       `json:"shadow_report"`
	LatencyPercentiles LatencyPercentilesResp  `json:"latency_percentiles"`
	TopFlaggedUsers    []UserCountResp        `json:"top_flagged_users"`
}

// SummaryStatsResp holds aggregate counts.
type SummaryStatsResp struct {
	TotalChecks int `json:"total_checks"`
	Blocks      int `json:"blocks"`
	Flags       int `json:"flags"`
	Allows      int `json:"allows"`
}

// TimeSeriesBucketResp holds an hourly count.
type TimeSeriesBucketResp struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// CategoryCountResp holds a category and its count.
type CategoryCountResp struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// ShadowReportResp holds shadow mode analysis.
type ShadowReportResp struct {
	Total      int `json:"total"`
	WouldBlock int `json:"would_block"`
	WouldFlag  int `json:"would_flag"`
}

// LatencyPercentilesResp holds latency percentiles.
type LatencyPercentilesResp struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
}

// UserCountResp holds a user_id and its count.
type UserCountResp struct {
	UserID string `json:"user_id"`
	Count  int    `json:"count"`
}

// ErrorResp is a standard error response body.
type ErrorResp struct {
	Detail string `json:"detail"`
}
