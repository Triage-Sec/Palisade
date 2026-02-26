package registry

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"go.uber.org/zap"
)

// mockToolStore is a test helper.
type mockToolStore struct {
	row *toolRow
	err error
}

func (m *mockToolStore) LookupTool(_ context.Context, _, _ string) (*toolRow, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.row, nil
}

func TestPostgresRegistry_CacheHit(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	callCount := 0
	store := &countingToolStore{
		row: &toolRow{
			ID:              "td-1",
			ProjectID:       "proj-1",
			ToolName:        "send_email",
			RiskTier:        "write",
			RequiresConfirm: false,
			Preconditions:   `["authenticate_user"]`,
			ArgumentPolicy:  `{}`,
			ContextualRules: `{}`,
			InformationFlow: `{}`,
		},
		callCount: &callCount,
	}
	reg := newPostgresToolRegistryWithStore(store, 30*time.Second, logger)

	// First call — cache miss
	td, err := reg.GetTool(context.Background(), "proj-1", "send_email")
	if err != nil {
		t.Fatal(err)
	}
	if td.ToolName != "send_email" {
		t.Fatalf("expected send_email, got %s", td.ToolName)
	}
	if callCount != 1 {
		t.Fatalf("expected 1 DB call, got %d", callCount)
	}

	// Second call — cache hit
	td, err = reg.GetTool(context.Background(), "proj-1", "send_email")
	if err != nil {
		t.Fatal(err)
	}
	if td.ToolName != "send_email" {
		t.Fatalf("expected send_email, got %s", td.ToolName)
	}
	if callCount != 1 {
		t.Fatalf("expected still 1 DB call (cache hit), got %d", callCount)
	}
}

func TestPostgresRegistry_ToolNotFound(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := &mockToolStore{err: sql.ErrNoRows}
	reg := newPostgresToolRegistryWithStore(store, 30*time.Second, logger)

	td, err := reg.GetTool(context.Background(), "proj-1", "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if td != nil {
		t.Fatal("expected nil for not-found tool")
	}
}

func TestPostgresRegistry_NegativeCache(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	callCount := 0
	store := &countingToolStoreWithErr{
		err:       sql.ErrNoRows,
		callCount: &callCount,
	}
	reg := newPostgresToolRegistryWithStore(store, 30*time.Second, logger)

	// First call — DB miss
	td, _ := reg.GetTool(context.Background(), "proj-1", "nonexistent")
	if td != nil {
		t.Fatal("expected nil")
	}
	if callCount != 1 {
		t.Fatalf("expected 1 DB call, got %d", callCount)
	}

	// Second call — negative cache hit (no DB call)
	td, _ = reg.GetTool(context.Background(), "proj-1", "nonexistent")
	if td != nil {
		t.Fatal("expected nil from negative cache")
	}
	if callCount != 1 {
		t.Fatalf("expected still 1 DB call (negative cache hit), got %d", callCount)
	}
}

func TestPostgresRegistry_ParsePreconditions(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := &mockToolStore{
		row: &toolRow{
			ID:              "td-1",
			ProjectID:       "proj-1",
			ToolName:        "transfer",
			RiskTier:        "destructive",
			RequiresConfirm: true,
			Preconditions:   `["auth_user","validate_account"]`,
			ArgumentPolicy:  `{"scan_for_pii":true}`,
			ContextualRules: `{"allowed_workflows":["support"]}`,
			InformationFlow: `{"blocked_source_labels":["pii"]}`,
		},
	}
	reg := newPostgresToolRegistryWithStore(store, 30*time.Second, logger)

	td, err := reg.GetTool(context.Background(), "proj-1", "transfer")
	if err != nil {
		t.Fatal(err)
	}
	if len(td.Preconditions) != 2 {
		t.Fatalf("expected 2 preconditions, got %d", len(td.Preconditions))
	}
	if td.Preconditions[0] != "auth_user" {
		t.Fatalf("expected auth_user, got %s", td.Preconditions[0])
	}
	if !td.ArgumentPolicy.ScanForPII {
		t.Fatal("expected scan_for_pii to be true")
	}
	if len(td.ContextualRules.AllowedWorkflows) != 1 {
		t.Fatalf("expected 1 allowed workflow, got %d", len(td.ContextualRules.AllowedWorkflows))
	}
	if len(td.InformationFlow.BlockedSourceLabels) != 1 {
		t.Fatalf("expected 1 blocked source label, got %d", len(td.InformationFlow.BlockedSourceLabels))
	}
}

func TestPostgresRegistry_DBError(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	store := &mockToolStore{err: context.DeadlineExceeded}
	reg := newPostgresToolRegistryWithStore(store, 30*time.Second, logger)

	_, err := reg.GetTool(context.Background(), "proj-1", "tool")
	if err == nil {
		t.Fatal("expected error on DB failure")
	}
}

// countingToolStore tracks how many times LookupTool is called.
type countingToolStore struct {
	row       *toolRow
	callCount *int
}

func (s *countingToolStore) LookupTool(_ context.Context, _, _ string) (*toolRow, error) {
	*s.callCount++
	return s.row, nil
}

type countingToolStoreWithErr struct {
	err       error
	callCount *int
}

func (s *countingToolStoreWithErr) LookupTool(_ context.Context, _, _ string) (*toolRow, error) {
	*s.callCount++
	return nil, s.err
}
