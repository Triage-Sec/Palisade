package evaluators

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Pre-compiled PII patterns for argument scanning.
var argPIIPatterns = []struct {
	re     *regexp.Regexp
	detail string
}{
	{regexp.MustCompile(`\b\d{3}[-\s]\d{2}[-\s]\d{4}\b`), "SSN"},
	{regexp.MustCompile(`\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`), "credit card (Visa)"},
	{regexp.MustCompile(`\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`), "credit card (Mastercard)"},
	{regexp.MustCompile(`\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b`), "credit card (Amex)"},
	{regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`), "email address"},
	{regexp.MustCompile(`\b\d{3}[-\s.]?\d{3}[-\s.]?\d{4}\b`), "phone number"},
}

// Pre-compiled injection patterns for argument scanning.
var argInjectionPatterns = []struct {
	re     *regexp.Regexp
	detail string
}{
	{regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\b.*\b(FROM|INTO|TABLE|SET|WHERE|ALL)\b`), "SQL injection"},
	{regexp.MustCompile(`(?i);\s*(rm|cat|curl|wget|chmod|chown|sudo|bash|sh|exec)\b`), "command injection"},
	{regexp.MustCompile(`(?i)(\||&&)\s*(rm|cat|curl|wget|chmod|chown|sudo|bash|sh)\b`), "command injection (pipe/chain)"},
	{regexp.MustCompile(`(?i)\$\(.*\)`), "command substitution"},
	{regexp.MustCompile("(?i)`[^`]*`"), "backtick command execution"},
}

// ArgumentValidationEvaluator validates tool arguments against schema, PII, and injection patterns.
type ArgumentValidationEvaluator struct{}

func NewArgumentValidationEvaluator() *ArgumentValidationEvaluator {
	return &ArgumentValidationEvaluator{}
}

func (e *ArgumentValidationEvaluator) Name() string {
	return "argument_validation"
}

func (e *ArgumentValidationEvaluator) Category() toolguardv1.EvalCategory {
	return toolguardv1.EvalCategory_EVAL_CATEGORY_ARGUMENT_VALIDATION
}

func (e *ArgumentValidationEvaluator) Evaluate(ctx context.Context, req *engine.EvalRequest) (*engine.EvalResult, error) {
	var issues []string
	var bestConfidence float32

	// 1. JSON Schema validation (only for registered tools with schema)
	if req.ToolDef != nil && req.ToolDef.ArgumentSchema != nil {
		if issue := validateSchema(req.ArgumentsJSON, req.ToolDef.ArgumentSchema); issue != "" {
			issues = append(issues, issue)
			if bestConfidence < 0.90 {
				bestConfidence = 0.90
			}
		}
	}

	if ctx.Err() != nil {
		return resultFromIssues(issues, bestConfidence), nil
	}

	// 2. PII scanning
	scanPII := req.ToolDef == nil || req.ToolDef.ArgumentPolicy.ScanForPII
	if scanPII {
		for _, p := range argPIIPatterns {
			if ctx.Err() != nil {
				break
			}
			if p.re.MatchString(req.ArgumentsJSON) {
				issues = append(issues, fmt.Sprintf("PII detected in arguments: %s", p.detail))
				if bestConfidence < 0.90 {
					bestConfidence = 0.90
				}
			}
		}
	}

	if ctx.Err() != nil {
		return resultFromIssues(issues, bestConfidence), nil
	}

	// 3. Injection scanning (always runs for unregistered tools as safety net)
	scanInjection := req.ToolDef == nil || req.ToolDef.ArgumentPolicy.ScanForInjection
	if scanInjection {
		for _, p := range argInjectionPatterns {
			if ctx.Err() != nil {
				break
			}
			if p.re.MatchString(req.ArgumentsJSON) {
				issues = append(issues, fmt.Sprintf("injection pattern in arguments: %s", p.detail))
				if bestConfidence < 0.95 {
					bestConfidence = 0.95
				}
			}
		}
	}

	if ctx.Err() != nil {
		return resultFromIssues(issues, bestConfidence), nil
	}

	// 4. Trace binding validation (only for registered tools)
	if req.ToolDef != nil && len(req.ToolDef.ArgumentPolicy.TraceBinding) > 0 {
		if issue := validateTraceBinding(req); issue != "" {
			issues = append(issues, issue)
			if bestConfidence < 0.90 {
				bestConfidence = 0.90
			}
		}
	}

	return resultFromIssues(issues, bestConfidence), nil
}

func resultFromIssues(issues []string, confidence float32) *engine.EvalResult {
	if len(issues) == 0 {
		return &engine.EvalResult{Triggered: false}
	}
	return &engine.EvalResult{
		Triggered:  true,
		Confidence: confidence,
		Details:    strings.Join(issues, "; "),
	}
}

func validateSchema(argsJSON string, schema map[string]any) string {
	schemaBytes, err := json.Marshal(schema)
	if err != nil {
		return fmt.Sprintf("invalid argument_schema: %v", err)
	}

	var schemaObj any
	if err := json.Unmarshal(schemaBytes, &schemaObj); err != nil {
		return fmt.Sprintf("schema unmarshal error: %v", err)
	}

	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", schemaObj); err != nil {
		return fmt.Sprintf("schema compile error: %v", err)
	}
	sch, err := c.Compile("schema.json")
	if err != nil {
		return fmt.Sprintf("schema compile error: %v", err)
	}

	var args any
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return fmt.Sprintf("arguments are not valid JSON: %v", err)
	}

	if err := sch.Validate(args); err != nil {
		return fmt.Sprintf("schema validation failed: %v", err)
	}

	return ""
}

// validateTraceBinding checks that argument values match previously established trace outputs.
func validateTraceBinding(req *engine.EvalRequest) string {
	if len(req.Trace) == 0 {
		return "trace binding requires trace entries but trace is empty"
	}

	var args map[string]any
	if err := json.Unmarshal([]byte(req.ArgumentsJSON), &args); err != nil {
		return "" // can't validate non-object args
	}

	// Build a map of trace results: "tool_name.result.path" → value
	traceValues := buildTraceValueMap(req.Trace)

	var mismatches []string
	for argName, tracePath := range req.ToolDef.ArgumentPolicy.TraceBinding {
		argVal, ok := args[argName]
		if !ok {
			continue // argument not present, schema validation handles required fields
		}

		traceVal, found := traceValues[tracePath]
		if !found {
			mismatches = append(mismatches, fmt.Sprintf("%s: trace path %q not found", argName, tracePath))
			continue
		}

		if fmt.Sprintf("%v", argVal) != fmt.Sprintf("%v", traceVal) {
			mismatches = append(mismatches, fmt.Sprintf("%s: expected %v from trace, got %v", argName, traceVal, argVal))
		}
	}

	if len(mismatches) > 0 {
		return "trace binding mismatch: " + strings.Join(mismatches, "; ")
	}
	return ""
}

// buildTraceValueMap extracts values from trace entries into a flat lookup map.
// Keys are "tool_name.result.field_name" for top-level fields in JSON results.
func buildTraceValueMap(trace []*toolguardv1.TraceEntry) map[string]any {
	values := make(map[string]any)
	for _, entry := range trace {
		if entry.ResultJson == "" {
			continue
		}
		var result map[string]any
		if err := json.Unmarshal([]byte(entry.ResultJson), &result); err != nil {
			continue
		}
		for key, val := range result {
			path := entry.ToolName + ".result." + key
			values[path] = val
		}
	}
	return values
}
