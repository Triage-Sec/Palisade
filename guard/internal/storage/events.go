package storage

import "time"

// EventWriter is the interface for writing security events.
// Write() must NEVER block the caller.
type EventWriter interface {
	Write(event *SecurityEvent)
	Close()
}

// SecurityEvent represents a single check() result to be persisted.
type SecurityEvent struct {
	RequestID           string
	ProjectID           string
	Timestamp           time.Time
	Action              string
	PayloadPreview      string // First 500 chars
	PayloadHash         string // SHA256 of full payload
	PayloadSize         uint32
	Verdict             string
	IsShadow            bool
	Reason              string
	DetectorNames       []string
	DetectorTriggered   []bool
	DetectorConfidences []float32
	DetectorCategories  []string
	DetectorDetails     []string
	UserID              string
	SessionID           string
	TenantID            string
	ClientTraceID       string
	ToolName            string
	ToolArguments       string
	Metadata            map[string]string
	LatencyMs           float32
	Source              string // "sdk" or "gateway"
	SDKLanguage         string
	SDKVersion          string
}

// PayloadPreviewLength is the max chars stored in payload_preview.
const PayloadPreviewLength = 500

// TruncatePayload returns the first N characters (runes) of a payload for
// preview storage. It never splits a multi-byte UTF-8 character.
func TruncatePayload(payload string, maxLen int) string {
	runes := []rune(payload)
	if len(runes) <= maxLen {
		return payload
	}
	return string(runes[:maxLen])
}
