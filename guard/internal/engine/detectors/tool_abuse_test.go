package detectors

import (
	"context"
	"testing"

	guardv1 "github.com/triage-ai/palisade/gen/guard/v1"
	"github.com/triage-ai/palisade/internal/engine"
)

func TestToolAbuseDetector_BlockedFunctions(t *testing.T) {
	d := NewToolAbuseDetector()
	ctx := context.Background()

	blockedFuncs := []string{"exec", "eval", "system", "rm", "rm -rf", "os.system", "shutdown", "kill", "dd", "chmod 777"}

	for _, fn := range blockedFuncs {
		t.Run("blocked_"+fn, func(t *testing.T) {
			result, err := d.Detect(ctx, &engine.DetectRequest{
				Payload: "some arguments",
				Action:  guardv1.ActionType_ACTION_TYPE_TOOL_CALL,
				ToolCall: &guardv1.ToolCall{
					FunctionName:  fn,
					ArgumentsJson: `{"path": "/tmp/test"}`,
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Triggered {
				t.Errorf("expected blocked function '%s' to trigger", fn)
			}
			if result.Confidence < 0.90 {
				t.Errorf("confidence %.2f too low for blocked function '%s'", result.Confidence, fn)
			}
		})
	}
}

func TestToolAbuseDetector_SafeFunctions(t *testing.T) {
	d := NewToolAbuseDetector()
	ctx := context.Background()

	safeFuncs := []string{"search", "get_weather", "calculate", "read_file", "list_users", "send_email"}

	for _, fn := range safeFuncs {
		t.Run("safe_"+fn, func(t *testing.T) {
			result, err := d.Detect(ctx, &engine.DetectRequest{
				Payload: `{"query": "hello"}`,
				Action:  guardv1.ActionType_ACTION_TYPE_TOOL_CALL,
				ToolCall: &guardv1.ToolCall{
					FunctionName:  fn,
					ArgumentsJson: `{"query": "hello"}`,
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Triggered {
				t.Errorf("false positive for safe function '%s' (detail: %s)", fn, result.Details)
			}
		})
	}
}

func TestToolAbuseDetector_SQLInjection(t *testing.T) {
	d := NewToolAbuseDetector()
	ctx := context.Background()

	tests := []struct {
		name    string
		payload string
	}{
		{"DROP TABLE", "SELECT * FROM users; DROP TABLE users;"},
		{"UNION SELECT", "SELECT id FROM users UNION SELECT password FROM admin"},
		{"OR 1=1", "SELECT * FROM users WHERE id = 1 OR 1=1"},
		{"comment injection", "SELECT * FROM users WHERE name = 'admin'--"},
		{"DELETE TABLE", "DELETE TABLE sessions"},
		{"TRUNCATE", "TRUNCATE TABLE audit_log"},
		{"xp_cmdshell", "EXEC xp_cmdshell 'dir'"},
		{"INTO OUTFILE", "SELECT * FROM users INTO OUTFILE '/tmp/dump'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := d.Detect(ctx, &engine.DetectRequest{
				Payload: tt.payload,
				Action:  guardv1.ActionType_ACTION_TYPE_DB_QUERY,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Triggered {
				t.Errorf("expected SQL injection detected for: %s", tt.payload)
			}
		})
	}
}

func TestToolAbuseDetector_CommandInjection(t *testing.T) {
	d := NewToolAbuseDetector()
	ctx := context.Background()

	tests := []struct {
		name    string
		payload string
	}{
		{"pipe to bash", "echo hello | bash"},
		{"semicolon cat", "file.txt; cat /etc/passwd"},
		{"backtick substitution", "filename=`whoami`"},
		{"dollar substitution", "path=$(cat /etc/shadow)"},
		{"write to etc", "data > /etc/crontab"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := d.Detect(ctx, &engine.DetectRequest{
				Payload: tt.payload,
				Action:  guardv1.ActionType_ACTION_TYPE_TOOL_CALL,
				ToolCall: &guardv1.ToolCall{
					FunctionName:  "run_command",
					ArgumentsJson: tt.payload,
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Triggered {
				t.Errorf("expected command injection detected for: %s", tt.payload)
			}
		})
	}
}

func TestToolAbuseDetector_SafeQueries(t *testing.T) {
	d := NewToolAbuseDetector()
	ctx := context.Background()

	safePayloads := []struct {
		name    string
		payload string
	}{
		{"simple select", "SELECT name, email FROM users WHERE id = 42"},
		{"insert", "INSERT INTO logs (message) VALUES ('user logged in')"},
		{"count", "SELECT COUNT(*) FROM orders WHERE status = 'active'"},
		{"normal text", "The quick brown fox jumps over the lazy dog"},
	}

	for _, tt := range safePayloads {
		t.Run(tt.name, func(t *testing.T) {
			result, err := d.Detect(ctx, &engine.DetectRequest{
				Payload: tt.payload,
				Action:  guardv1.ActionType_ACTION_TYPE_DB_QUERY,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Triggered {
				t.Errorf("false positive for safe query: %s (detail: %s)", tt.payload, result.Details)
			}
		})
	}
}

func TestToolAbuseDetector_NoToolCall(t *testing.T) {
	d := NewToolAbuseDetector()
	ctx := context.Background()

	// Non-tool actions with safe payloads should not trigger
	result, err := d.Detect(ctx, &engine.DetectRequest{
		Payload: "What is the weather today?",
		Action:  guardv1.ActionType_ACTION_TYPE_LLM_INPUT,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Triggered {
		t.Errorf("should not trigger on non-tool LLM input")
	}
}

func BenchmarkToolAbuseDetector_Safe(b *testing.B) {
	d := NewToolAbuseDetector()
	ctx := context.Background()
	req := &engine.DetectRequest{
		Payload: `{"query": "SELECT name FROM users WHERE id = 42"}`,
		Action:  guardv1.ActionType_ACTION_TYPE_TOOL_CALL,
		ToolCall: &guardv1.ToolCall{
			FunctionName:  "run_query",
			ArgumentsJson: `{"query": "SELECT name FROM users WHERE id = 42"}`,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(ctx, req)
	}
}

func BenchmarkToolAbuseDetector_SQLInjection(b *testing.B) {
	d := NewToolAbuseDetector()
	ctx := context.Background()
	req := &engine.DetectRequest{
		Payload: "SELECT * FROM users; DROP TABLE users;",
		Action:  guardv1.ActionType_ACTION_TYPE_DB_QUERY,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = d.Detect(ctx, req)
	}
}
