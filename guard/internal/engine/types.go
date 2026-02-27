package engine

// Verdict represents the final enforcement decision.
type Verdict int

const (
	VerdictAllow Verdict = iota + 1
	VerdictBlock
	VerdictFlag
)

// String returns the lowercase verdict name.
func (v Verdict) String() string {
	switch v {
	case VerdictAllow:
		return "allow"
	case VerdictBlock:
		return "block"
	case VerdictFlag:
		return "flag"
	default:
		return "unspecified"
	}
}

// ActionType represents what kind of AI operation is being checked.
type ActionType int

const (
	ActionUnspecified    ActionType = iota
	ActionLLMInput                 // llm_input
	ActionLLMOutput                // llm_output
	ActionToolCall                 // tool_call
	ActionToolResult               // tool_result
	ActionRAGRetrieval             // rag_retrieval
	ActionChainOfThought           // chain_of_thought
	ActionDBQuery                  // db_query
	ActionCustom                   // custom
)

// ThreatCategory classifies the type of threat a detector covers.
type ThreatCategory int

const (
	CategoryUnspecified       ThreatCategory = iota
	CategoryPromptInjection                  // prompt_injection
	CategoryJailbreak                        // jailbreak
	CategoryPIILeakage                       // pii_leakage
	CategoryContentModeration                // content_moderation
	CategoryToolAbuse                        // tool_abuse
	CategoryDataExfiltration                 // data_exfiltration
	CategoryCustomRule                       // custom_rule
)

// String returns the proto-compatible string (used for ClickHouse storage).
func (c ThreatCategory) String() string {
	switch c {
	case CategoryPromptInjection:
		return "THREAT_CATEGORY_PROMPT_INJECTION"
	case CategoryJailbreak:
		return "THREAT_CATEGORY_JAILBREAK"
	case CategoryPIILeakage:
		return "THREAT_CATEGORY_PII_LEAKAGE"
	case CategoryContentModeration:
		return "THREAT_CATEGORY_CONTENT_MODERATION"
	case CategoryToolAbuse:
		return "THREAT_CATEGORY_TOOL_ABUSE"
	case CategoryDataExfiltration:
		return "THREAT_CATEGORY_DATA_EXFILTRATION"
	case CategoryCustomRule:
		return "THREAT_CATEGORY_CUSTOM_RULE"
	default:
		return "THREAT_CATEGORY_UNSPECIFIED"
	}
}

// ToolCall contains tool invocation details.
type ToolCall struct {
	FunctionName  string
	ArgumentsJSON string
}

// DetectorResult is the output from a single detector run within the engine.
type DetectorResult struct {
	Detector   string
	Triggered  bool
	Confidence float32
	Category   ThreatCategory
	Details    string
}
