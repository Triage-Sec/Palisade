package server

import (
	"context"
	"net"
	"testing"
	"time"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/auth"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine/evaluators"
	"github.com/triage-ai/palisade/services/tool_guard/internal/registry"
	"github.com/triage-ai/palisade/services/tool_guard/internal/storage"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// stubRegistry returns a fixed tool definition.
type stubRegistry struct {
	tools map[string]*registry.ToolDefinition
}

func (s *stubRegistry) GetTool(_ context.Context, _, toolName string) (*registry.ToolDefinition, error) {
	if s.tools == nil {
		return nil, nil
	}
	return s.tools[toolName], nil
}

// setupTestServer creates a real gRPC server+client for integration testing.
func setupTestServer(t *testing.T, reg registry.ToolRegistry) (toolguardv1.ToolGuardServiceClient, func()) {
	t.Helper()
	logger, _ := zap.NewDevelopment()

	evals := []engine.Evaluator{
		evaluators.NewRiskTierEvaluator(),
		evaluators.NewPreconditionEvaluator(),
		evaluators.NewArgumentValidationEvaluator(),
		evaluators.NewContextualRulesEvaluator(),
		evaluators.NewInformationFlowEvaluator(),
	}

	eng := engine.NewToolGuardEngine(evals, 100*time.Millisecond, logger)
	writer := storage.NewLogWriter(logger)

	srv := NewToolGuardServer(
		eng,
		auth.NewStaticAuthenticator(),
		reg,
		writer,
		engine.DefaultAggregatorConfig(),
		logger,
	)

	grpcServer := grpc.NewServer()
	toolguardv1.RegisterToolGuardServiceServer(grpcServer, srv)

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		_ = grpcServer.Serve(lis)
	}()

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}

	client := toolguardv1.NewToolGuardServiceClient(conn)

	cleanup := func() {
		_ = conn.Close()
		grpcServer.Stop()
	}

	return client, cleanup
}

func authCtx() context.Context {
	md := metadata.New(map[string]string{
		"authorization": "Bearer tsk_testkey1234",
	})
	return metadata.NewOutgoingContext(context.Background(), md)
}

func TestServer_SafeToolCall(t *testing.T) {
	client, cleanup := setupTestServer(t, &stubRegistry{
		tools: map[string]*registry.ToolDefinition{
			"get_weather": {
				ToolName: "get_weather",
				RiskTier: "read",
				ArgumentPolicy: registry.ArgumentPolicy{
					ScanForPII:       true,
					ScanForInjection: true,
				},
			},
		},
	})
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "get_weather",
		ArgumentsJson: `{"city":"San Francisco"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE {
		t.Fatalf("expected SAFE, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
	if resp.RequestId == "" {
		t.Fatal("expected non-empty request_id")
	}
	if resp.LatencyMs <= 0 {
		t.Fatal("expected positive latency_ms")
	}
}

func TestServer_UnsafeToolCall_MissingPreconditions(t *testing.T) {
	client, cleanup := setupTestServer(t, &stubRegistry{
		tools: map[string]*registry.ToolDefinition{
			"transfer_funds": {
				ToolName:      "transfer_funds",
				RiskTier:      "destructive",
				Preconditions: []string{"authenticate_user", "validate_account"},
				ArgumentPolicy: registry.ArgumentPolicy{
					ScanForPII:       false,
					ScanForInjection: false,
				},
			},
		},
	})
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "transfer_funds",
		ArgumentsJson: `{"amount":100}`,
		Trace:         nil, // no trace = all preconditions missing
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("expected UNSAFE, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestServer_NeedsConfirmation(t *testing.T) {
	client, cleanup := setupTestServer(t, &stubRegistry{
		tools: map[string]*registry.ToolDefinition{
			"delete_account": {
				ToolName:        "delete_account",
				RiskTier:        "destructive",
				RequiresConfirm: true,
				ArgumentPolicy: registry.ArgumentPolicy{
					ScanForPII:       false,
					ScanForInjection: false,
				},
			},
		},
	})
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "delete_account",
		ArgumentsJson: `{}`,
		UserConfirmed: false,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_NEEDS_CONFIRMATION {
		t.Fatalf("expected NEEDS_CONFIRMATION, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestServer_ConfirmedDestructiveTool(t *testing.T) {
	client, cleanup := setupTestServer(t, &stubRegistry{
		tools: map[string]*registry.ToolDefinition{
			"delete_account": {
				ToolName:        "delete_account",
				RiskTier:        "destructive",
				RequiresConfirm: true,
				ArgumentPolicy: registry.ArgumentPolicy{
					ScanForPII:       false,
					ScanForInjection: false,
				},
			},
		},
	})
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "delete_account",
		ArgumentsJson: `{}`,
		UserConfirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE {
		t.Fatalf("expected SAFE for confirmed destructive tool, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestServer_UnregisteredTool(t *testing.T) {
	client, cleanup := setupTestServer(t, &stubRegistry{})
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "totally_unknown",
		ArgumentsJson: `{"data":"clean data"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Unregistered tool: risk_tier fires at 0.5 confidence (below 0.8 threshold) → SAFE
	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_SAFE {
		t.Fatalf("expected SAFE for unregistered tool (low confidence), got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestServer_UnregisteredToolWithInjection(t *testing.T) {
	client, cleanup := setupTestServer(t, &stubRegistry{})
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "totally_unknown",
		ArgumentsJson: `{"query":"SELECT * FROM users WHERE 1=1; DROP TABLE users"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Verdict != toolguardv1.SafetyVerdict_SAFETY_VERDICT_UNSAFE {
		t.Fatalf("expected UNSAFE for injection in unregistered tool, got %v (reason: %s)", resp.Verdict, resp.Reason)
	}
}

func TestServer_OutputRestrictions(t *testing.T) {
	client, cleanup := setupTestServer(t, &stubRegistry{
		tools: map[string]*registry.ToolDefinition{
			"query_user_data": {
				ToolName: "query_user_data",
				RiskTier: "read",
				ArgumentPolicy: registry.ArgumentPolicy{
					ScanForPII:       false,
					ScanForInjection: false,
				},
				InformationFlow: registry.InformationFlow{
					OutputRestrictions: []string{"redact_pii", "do_not_forward_to:external_api"},
				},
			},
		},
	})
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "query_user_data",
		ArgumentsJson: `{}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(resp.OutputRestrictions) != 2 {
		t.Fatalf("expected 2 output restrictions, got %d", len(resp.OutputRestrictions))
	}
}

func TestServer_UnauthenticatedRequest(t *testing.T) {
	client, cleanup := setupTestServer(t, &stubRegistry{})
	defer cleanup()

	// No auth metadata
	_, err := client.Check(context.Background(), &toolguardv1.ToolCheckRequest{
		ToolName:      "test",
		ArgumentsJson: `{}`,
	})
	if err == nil {
		t.Fatal("expected error for unauthenticated request")
	}
}

func TestServer_FiveEvaluators(t *testing.T) {
	client, cleanup := setupTestServer(t, &stubRegistry{
		tools: map[string]*registry.ToolDefinition{
			"send_email": {
				ToolName:      "send_email",
				RiskTier:      "write",
				Preconditions: []string{"auth"},
				ArgumentPolicy: registry.ArgumentPolicy{
					ScanForPII:       true,
					ScanForInjection: true,
				},
				ContextualRules: registry.ContextualRules{
					AllowedWorkflows: []string{"support"},
				},
				InformationFlow: registry.InformationFlow{
					BlockedSourceLabels: []string{"internal"},
				},
			},
		},
	})
	defer cleanup()

	resp, err := client.Check(authCtx(), &toolguardv1.ToolCheckRequest{
		ToolName:      "send_email",
		ArgumentsJson: `{"to":"user@example.com","body":"Hello"}`,
		WorkflowType:  "support",
		Trace: []*toolguardv1.TraceEntry{
			{ToolName: "auth"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// All 5 evaluators should return results
	if len(resp.Evaluations) != 5 {
		t.Fatalf("expected 5 evaluation results, got %d", len(resp.Evaluations))
	}
}
