package storage

import "time"

// EventWriter is the interface for writing tool check events.
// Write() must NEVER block the caller.
type EventWriter interface {
	Write(event *ToolCheckEvent)
	Close()
}

// ToolCheckEvent represents a single tool guard check result to be persisted.
type ToolCheckEvent struct {
	RequestID       string
	ProjectID       string
	Timestamp       time.Time
	ToolName        string
	ArgumentsJSON   string
	Verdict         string // "safe", "unsafe", "needs_confirmation"
	Reason          string
	EvalCategories  []string
	EvalTriggered   []bool
	EvalConfidences []float32
	EvalDetails     []string
	UserID          string
	SessionID       string
	TenantID        string
	ClientTraceID   string
	WorkflowType    string
	UserConfirmed   bool
	TraceLength     int32
	Metadata        map[string]string
	LatencyMs       float32
	Source          string
}
