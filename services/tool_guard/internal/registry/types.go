package registry

// ToolDefinition represents a tool registered for a project.
// Loaded from the tool_definitions table.
type ToolDefinition struct {
	ID                string
	ProjectID         string
	ToolName          string
	Description       string
	RiskTier          string // "read", "write", "destructive"
	RequiresConfirm   bool
	Preconditions     []string
	ArgumentSchema    map[string]any // JSON Schema, nil if not set
	ArgumentPolicy    ArgumentPolicy
	ContextualRules   ContextualRules
	InformationFlow   InformationFlow
}

// ArgumentPolicy controls argument-level scanning and trace binding.
type ArgumentPolicy struct {
	ScanForPII       bool              `json:"scan_for_pii"`
	ScanForInjection bool              `json:"scan_for_injection"`
	TraceBinding     map[string]string `json:"trace_binding"` // arg_name → "tool.result.path"
}

// ContextualRules controls workflow and rate-limit constraints.
type ContextualRules struct {
	AllowedWorkflows  []string  `json:"allowed_workflows"`
	BlockedWorkflows  []string  `json:"blocked_workflows"`
	RateLimit         *RateLimit `json:"rate_limit"`
}

// RateLimit defines a sliding-window rate constraint.
type RateLimit struct {
	MaxCalls      int `json:"max_calls"`
	WindowSeconds int `json:"window_seconds"`
}

// InformationFlow controls cross-tool data propagation rules.
type InformationFlow struct {
	BlockedSourceLabels  []string `json:"blocked_source_labels"`
	OutputLabels         []string `json:"output_labels"`
	OutputRestrictions   []string `json:"output_restrictions"`
}
