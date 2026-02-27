package detectors

import (
	"context"
	"regexp"
	"strings"

	"github.com/triage-ai/palisade/internal/engine"
)

// Dangerous function names that should never be called by an AI agent.
var blockedFunctionNames = map[string]bool{
	"exec":       true,
	"eval":       true,
	"system":     true,
	"popen":      true,
	"subprocess": true,
	"os.system":  true,
	"os.exec":    true,
	"os.popen":   true,
	"rm":         true,
	"rm -rf":     true,
	"rmdir":      true,
	"del":        true,
	"format":     true,
	"fdisk":      true,
	"mkfs":       true,
	"dd":         true,
	"shutdown":   true,
	"reboot":     true,
	"kill":       true,
	"killall":    true,
	"chmod 777":  true,
}

// SQL injection patterns in tool arguments.
var sqlInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(DROP|DELETE|TRUNCATE|ALTER)\s+(TABLE|DATABASE|INDEX|SCHEMA)\b`),
	regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\b`),
	regexp.MustCompile(`(?i);\s*(DROP|DELETE|TRUNCATE|ALTER|INSERT|UPDATE)\b`),
	regexp.MustCompile(`(?i)\bOR\s+1\s*=\s*1\b`),
	regexp.MustCompile(`(?i)\bOR\s+'[^']*'\s*=\s*'[^']*'`),
	regexp.MustCompile(`(?i)--\s*$`),
	regexp.MustCompile(`(?i)\bEXEC\s*\(`),
	regexp.MustCompile(`(?i)\bxp_cmdshell\b`),
	regexp.MustCompile(`(?i)\bINTO\s+OUTFILE\b`),
	regexp.MustCompile(`(?i)\bLOAD_FILE\s*\(`),
}

// Command injection patterns in tool arguments.
var commandInjectionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[;&|]\s*(cat|ls|pwd|whoami|id|uname|curl|wget|nc|ncat|bash|sh|zsh|python|perl|ruby|php)\b`),
	regexp.MustCompile("`[^`]+`"),            // Backtick command substitution
	regexp.MustCompile(`\$\([^)]+\)`),        // $() command substitution
	regexp.MustCompile(`\|\s*(bash|sh|zsh)`), // Pipe to shell
	regexp.MustCompile(`>\s*/etc/`),          // Write to /etc/
	regexp.MustCompile(`>\s*/tmp/`),          // Write to /tmp/
}

// ToolAbuseDetector checks tool calls for dangerous functions and injection attacks.
type ToolAbuseDetector struct{}

func NewToolAbuseDetector() *ToolAbuseDetector {
	return &ToolAbuseDetector{}
}

func (d *ToolAbuseDetector) Name() string {
	return "tool_abuse"
}

func (d *ToolAbuseDetector) Category() engine.ThreatCategory {
	return engine.CategoryToolAbuse
}

func (d *ToolAbuseDetector) Detect(ctx context.Context, req *engine.DetectRequest) (*engine.DetectResult, error) {
	// This detector primarily targets TOOL_CALL and DB_QUERY actions,
	// but also scans any payload for SQL/command injection patterns.
	var bestConfidence float32
	var bestDetail string

	// Per-project tool allow/block lists (from policy) take priority.
	if req.ToolCall != nil {
		funcName := strings.ToLower(req.ToolCall.FunctionName)

		// Allowlist: if set, tool MUST be in the list
		if len(req.ToolAllowList) > 0 && !stringInSlice(funcName, req.ToolAllowList) {
			return &engine.DetectResult{
				Triggered:  true,
				Confidence: 0.90,
				Details:    "tool not in project allowlist: " + req.ToolCall.FunctionName,
			}, nil
		}

		// Per-project blocklist
		if stringInSlice(funcName, req.ToolBlockList) {
			return &engine.DetectResult{
				Triggered:  true,
				Confidence: 0.95,
				Details:    "tool in project blocklist: " + req.ToolCall.FunctionName,
			}, nil
		}

		// Global blocklist
		if blockedFunctionNames[funcName] {
			return &engine.DetectResult{
				Triggered:  true,
				Confidence: 0.95,
				Details:    "blocked function: " + req.ToolCall.FunctionName,
			}, nil
		}
	}

	// Scan both the payload and the tool call arguments for injection patterns.
	// Malicious content can appear in either field.
	targets := []string{req.Payload}
	if req.ToolCall != nil && req.ToolCall.ArgumentsJSON != "" {
		targets = append(targets, req.ToolCall.ArgumentsJSON)
	}

	// SQL injection patterns
	for _, target := range targets {
		for _, p := range sqlInjectionPatterns {
			if ctx.Err() != nil {
				break
			}
			if p.MatchString(target) {
				if bestConfidence < 0.90 {
					bestConfidence = 0.90
					bestDetail = "SQL injection pattern detected"
				}
			}
		}
	}

	// Command injection patterns (only for tool calls and DB queries)
	if req.Action == engine.ActionToolCall ||
		req.Action == engine.ActionDBQuery {
		for _, target := range targets {
			for _, p := range commandInjectionPatterns {
				if ctx.Err() != nil {
					break
				}
				if p.MatchString(target) {
					if bestConfidence < 0.90 {
						bestConfidence = 0.90
						bestDetail = "command injection pattern detected"
					}
				}
			}
		}
	}

	if bestConfidence > 0 {
		return &engine.DetectResult{
			Triggered:  true,
			Confidence: bestConfidence,
			Details:    bestDetail,
		}, nil
	}

	return &engine.DetectResult{
		Triggered:  false,
		Confidence: 0,
	}, nil
}

// stringInSlice checks if a lowercased string exists in a slice.
func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if strings.ToLower(v) == s {
			return true
		}
	}
	return false
}
