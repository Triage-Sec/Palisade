package evaluators

import (
	"context"
	"strings"
	"testing"

	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
	"github.com/triage-ai/palisade/services/tool_guard/internal/registry"
)

func TestInfoFlow_TaintedDataInArgs(t *testing.T) {
	e := NewInformationFlowEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "send_to_external",
		ArgumentsJSON: `{"data":"secret_value_12345"}`,
		Trace: []*toolguardv1.TraceEntry{
			{
				ToolName:     "get_internal_data",
				ResultJson:   `{"secret":"secret_value_12345"}`,
				OutputLabels: []string{"internal"},
			},
		},
		ToolDef: &registry.ToolDefinition{
			InformationFlow: registry.InformationFlow{
				BlockedSourceLabels: []string{"internal"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Triggered {
		t.Fatal("expected triggered when tainted data flows into arguments")
	}
	if !strings.Contains(result.Details, "tainted data") {
		t.Fatalf("expected tainted data detail, got: %s", result.Details)
	}
}

func TestInfoFlow_NoTaintedData(t *testing.T) {
	e := NewInformationFlowEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "send_to_external",
		ArgumentsJSON: `{"data":"clean_data"}`,
		Trace: []*toolguardv1.TraceEntry{
			{
				ToolName:     "get_internal_data",
				ResultJson:   `{"secret":"secret_value_12345"}`,
				OutputLabels: []string{"internal"},
			},
		},
		ToolDef: &registry.ToolDefinition{
			InformationFlow: registry.InformationFlow{
				BlockedSourceLabels: []string{"internal"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered when tainted data is not in arguments")
	}
}

func TestInfoFlow_ShortValuesIgnored(t *testing.T) {
	e := NewInformationFlowEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "send_email",
		ArgumentsJSON: `{"to":"ok"}`,
		Trace: []*toolguardv1.TraceEntry{
			{
				ToolName:     "get_status",
				ResultJson:   `{"status":"ok"}`,
				OutputLabels: []string{"pii"},
			},
		},
		ToolDef: &registry.ToolDefinition{
			InformationFlow: registry.InformationFlow{
				BlockedSourceLabels: []string{"pii"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered for short substring matches (< 4 chars)")
	}
}

func TestInfoFlow_NoBlockedLabels(t *testing.T) {
	e := NewInformationFlowEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "send_email",
		ArgumentsJSON: `{"data":"anything"}`,
		ToolDef: &registry.ToolDefinition{
			InformationFlow: registry.InformationFlow{
				BlockedSourceLabels: nil,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered when no blocked source labels defined")
	}
}

func TestInfoFlow_UnregisteredTool(t *testing.T) {
	e := NewInformationFlowEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "unknown",
		ArgumentsJSON: `{"data":"anything"}`,
		ToolDef:       nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered for unregistered tool")
	}
}

func TestInfoFlow_LabelMismatch(t *testing.T) {
	e := NewInformationFlowEvaluator()
	result, err := e.Evaluate(context.Background(), &engine.EvalRequest{
		ToolName:      "send_email",
		ArgumentsJSON: `{"data":"secret_data_here"}`,
		Trace: []*toolguardv1.TraceEntry{
			{
				ToolName:     "get_data",
				ResultJson:   `{"value":"secret_data_here"}`,
				OutputLabels: []string{"public"}, // not blocked
			},
		},
		ToolDef: &registry.ToolDefinition{
			InformationFlow: registry.InformationFlow{
				BlockedSourceLabels: []string{"internal"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Triggered {
		t.Fatal("expected not triggered when trace labels don't match blocked labels")
	}
}
