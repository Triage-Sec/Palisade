package auth

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/triage-ai/palisade/internal/engine"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/metadata"
)

// testAPIKey is the raw API key used in tests. Must start with "tsk_" and be >= 8 chars.
const testAPIKey = "tsk_test_valid_key_1234567890abcdef"

// testHash returns a bcrypt hash of testAPIKey using MinCost (fast for tests).
func testHash(t *testing.T) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(testAPIKey), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("failed to generate bcrypt hash: %v", err)
	}
	return string(hash)
}

// mockStore implements ProjectStore for testing.
type mockStore struct {
	row       *projectRow
	err       error
	callCount atomic.Int32
}

func (m *mockStore) LookupByPrefix(_ context.Context, _ string) (*projectRow, error) {
	m.callCount.Add(1)
	if m.err != nil {
		return nil, m.err
	}
	return m.row, nil
}

// authedCtx creates a gRPC incoming context with the test API key.
func pgAuthedCtx() context.Context {
	md := metadata.Pairs(
		"authorization", "Bearer "+testAPIKey,
		"x-project-id", "proj_test_123",
	)
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestPostgresAuth_CacheMiss_ValidKey(t *testing.T) {
	store := &mockStore{
		row: &projectRow{
			ProjectID:  "proj_abc",
			APIKeyHash: testHash(t),
			Mode:       "enforce",
			FailOpen:   true,
		},
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	project, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if project.ProjectID != "proj_abc" {
		t.Errorf("expected project ID proj_abc, got %s", project.ProjectID)
	}
	if project.Mode != "enforce" {
		t.Errorf("expected mode enforce, got %s", project.Mode)
	}
	if !project.FailOpen {
		t.Error("expected fail_open=true")
	}
	if project.Policy != nil {
		t.Error("expected nil policy (no detector_config)")
	}
	if store.callCount.Load() != 1 {
		t.Errorf("expected 1 DB call, got %d", store.callCount.Load())
	}
}

func TestPostgresAuth_CacheHit_NoDBCall(t *testing.T) {
	store := &mockStore{
		row: &projectRow{
			ProjectID:  "proj_abc",
			APIKeyHash: testHash(t),
			Mode:       "enforce",
			FailOpen:   true,
		},
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	// First call — cache miss, hits DB
	_, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if store.callCount.Load() != 1 {
		t.Fatalf("expected 1 DB call after first auth, got %d", store.callCount.Load())
	}

	// Second call — cache hit, no DB call
	project, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if store.callCount.Load() != 1 {
		t.Errorf("expected still 1 DB call (cache hit), got %d", store.callCount.Load())
	}
	if project.ProjectID != "proj_abc" {
		t.Errorf("expected proj_abc from cache, got %s", project.ProjectID)
	}
}

func TestPostgresAuth_CacheMiss_InvalidKey(t *testing.T) {
	store := &mockStore{
		row: &projectRow{
			ProjectID:  "proj_abc",
			APIKeyHash: testHash(t), // Hash of testAPIKey
			Mode:       "enforce",
			FailOpen:   true,
		},
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	// Use a different API key that won't match the bcrypt hash
	md := metadata.Pairs(
		"authorization", "Bearer tsk_wrong_key_doesnt_match_hash_at_all",
		"x-project-id", "proj_test",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := auth.Authenticate(ctx)
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey, got: %v", err)
	}
}

func TestPostgresAuth_ProjectNotFound(t *testing.T) {
	// The real sqlProjectStore converts sql.ErrNoRows → ErrInvalidAPIKey.
	// The mock simulates that behavior.
	store := &mockStore{
		err: ErrInvalidAPIKey,
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	_, err := auth.Authenticate(pgAuthedCtx())
	if err == nil {
		t.Fatal("expected error for project not found, got nil")
	}
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey, got: %v", err)
	}
}

func TestPostgresAuth_DBDown_ReturnsUnavailable(t *testing.T) {
	store := &mockStore{
		err: errors.New("connection refused"),
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	_, err := auth.Authenticate(pgAuthedCtx())
	if err == nil {
		t.Fatal("expected error when DB is down, got nil")
	}
	if !errors.Is(err, ErrAuthUnavailable) {
		t.Errorf("expected ErrAuthUnavailable, got: %v", err)
	}
}

func TestPostgresAuth_InvalidKey_AlwaysRejected(t *testing.T) {
	// An invalid API key (bcrypt mismatch) should always be rejected
	store := &mockStore{
		row: &projectRow{
			ProjectID:  "proj_abc",
			APIKeyHash: testHash(t),
			Mode:       "enforce",
			FailOpen:   true,
		},
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	md := metadata.Pairs(
		"authorization", "Bearer tsk_wrong_key_doesnt_match_hash_at_all",
		"x-project-id", "proj_test",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := auth.Authenticate(ctx)
	if err == nil {
		t.Fatal("expected error for invalid key")
	}
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Errorf("expected ErrInvalidAPIKey, got: %v", err)
	}
}

func TestPostgresAuth_PolicyParsing(t *testing.T) {
	store := &mockStore{
		row: &projectRow{
			ProjectID:  "proj_with_policy",
			APIKeyHash: testHash(t),
			Mode:       "shadow",
			FailOpen:   false,
			DetectorConfig: sql.NullString{
				// DB stores flat map, not wrapped in "detectors" key
				String: `{"prompt_injection": {"enabled": true, "block_threshold": 0.95}, "pii": {"enabled": false}}`,
				Valid:  true,
			},
		},
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	project, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if project.Mode != "shadow" {
		t.Errorf("expected shadow mode, got %s", project.Mode)
	}
	if project.Policy == nil {
		t.Fatal("expected non-nil policy")
	}

	// Check prompt_injection policy
	pi := project.Policy.GetDetectorPolicy("prompt_injection")
	if !pi.IsEnabled() {
		t.Error("prompt_injection should be enabled")
	}
	if got := pi.EffectiveBlockThreshold(0.8); got != 0.95 {
		t.Errorf("expected block_threshold 0.95, got %f", got)
	}

	// Check pii policy — disabled
	pii := project.Policy.GetDetectorPolicy("pii")
	if pii.IsEnabled() {
		t.Error("pii should be disabled")
	}

	// Check unknown detector — defaults
	unknown := project.Policy.GetDetectorPolicy("jailbreak")
	if !unknown.IsEnabled() {
		t.Error("unlisted detector should default to enabled")
	}
}

func TestPostgresAuth_PolicyParsing_ToolAbuse(t *testing.T) {
	store := &mockStore{
		row: &projectRow{
			ProjectID:  "proj_tools",
			APIKeyHash: testHash(t),
			Mode:       "enforce",
			FailOpen:   true,
			DetectorConfig: sql.NullString{
				String: `{"tool_abuse": {"enabled": true, "allowed_tools": ["search", "calculator"], "blocked_tools": ["exec"]}}`,
				Valid:  true,
			},
		},
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	project, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	ta := project.Policy.GetDetectorPolicy("tool_abuse")
	if len(ta.AllowedTools) != 2 {
		t.Errorf("expected 2 allowed tools, got %d", len(ta.AllowedTools))
	}
	if len(ta.BlockedTools) != 1 || ta.BlockedTools[0] != "exec" {
		t.Errorf("expected blocked_tools [exec], got %v", ta.BlockedTools)
	}
}

func TestPostgresAuth_EmptyDetectorConfig(t *testing.T) {
	store := &mockStore{
		row: &projectRow{
			ProjectID:  "proj_empty",
			APIKeyHash: testHash(t),
			Mode:       "enforce",
			FailOpen:   true,
			DetectorConfig: sql.NullString{
				String: "{}",
				Valid:  true,
			},
		},
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	project, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Empty "{}" should result in nil policy (server defaults)
	if project.Policy != nil {
		t.Error("expected nil policy for empty detector_config")
	}
}

func TestPostgresAuth_NullDetectorConfig(t *testing.T) {
	store := &mockStore{
		row: &projectRow{
			ProjectID:  "proj_null",
			APIKeyHash: testHash(t),
			Mode:       "enforce",
			FailOpen:   true,
			DetectorConfig: sql.NullString{
				Valid: false, // NULL in DB
			},
		},
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	project, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if project.Policy != nil {
		t.Error("expected nil policy for NULL detector_config")
	}
}

func TestPostgresAuth_InvalidJSON_FallsBackToDefaults(t *testing.T) {
	store := &mockStore{
		row: &projectRow{
			ProjectID:  "proj_bad_json",
			APIKeyHash: testHash(t),
			Mode:       "enforce",
			FailOpen:   true,
			DetectorConfig: sql.NullString{
				String: `not valid json!!!`,
				Valid:  true,
			},
		},
	}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	// Should not fail — just use nil policy
	project, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("expected no error (graceful fallback), got: %v", err)
	}
	if project.Policy != nil {
		t.Error("expected nil policy for invalid JSON")
	}
}

func TestPostgresAuth_MissingAPIKey(t *testing.T) {
	store := &mockStore{}
	cache := NewAuthCache(1 * time.Minute)
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	// No auth metadata
	_, err := auth.Authenticate(context.Background())
	if err == nil {
		t.Fatal("expected error for missing API key")
	}
	// DB should never be called
	if store.callCount.Load() != 0 {
		t.Error("DB should not be called when API key is missing")
	}
}

func TestPostgresAuth_StaleHit_ServesStaleAndRefreshes(t *testing.T) {
	hash := testHash(t)
	store := &mockStore{
		row: &projectRow{
			ProjectID:  "proj_stale",
			APIKeyHash: hash,
			Mode:       "enforce",
			FailOpen:   true,
		},
	}
	cache := NewAuthCache(1 * time.Millisecond) // Very short TTL
	auth := newPostgresAuthenticatorWithStore(store, cache, zap.NewNop())

	// First call — cache miss
	project, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if project.ProjectID != "proj_stale" {
		t.Fatalf("expected proj_stale, got %s", project.ProjectID)
	}
	if store.callCount.Load() != 1 {
		t.Fatalf("expected 1 DB call, got %d", store.callCount.Load())
	}

	// Wait for cache to expire
	time.Sleep(5 * time.Millisecond)

	// Update what the store returns so we can verify refresh happened
	store.row = &projectRow{
		ProjectID:  "proj_stale",
		APIKeyHash: hash,
		Mode:       "shadow", // Changed!
		FailOpen:   true,
	}

	// Second call — stale hit, returns old value immediately
	project2, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	// Should return stale value (mode=enforce, not shadow yet)
	if project2.Mode != "enforce" {
		t.Errorf("stale hit should return old mode=enforce, got %s", project2.Mode)
	}

	// Wait for background refresh to complete
	time.Sleep(200 * time.Millisecond)

	// Third call — should now have refreshed value
	project3, err := auth.Authenticate(pgAuthedCtx())
	if err != nil {
		t.Fatalf("third call failed: %v", err)
	}
	if project3.Mode != "shadow" {
		t.Errorf("expected refreshed mode=shadow, got %s", project3.Mode)
	}
}

func TestParseDetectorConfig(t *testing.T) {
	raw := `{"prompt_injection": {"enabled": true, "block_threshold": 0.9}, "pii": {"enabled": false}}`
	pc, err := parseDetectorConfig(raw)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if len(pc.Detectors) != 2 {
		t.Errorf("expected 2 detectors, got %d", len(pc.Detectors))
	}

	pi := pc.GetDetectorPolicy("prompt_injection")
	if !pi.IsEnabled() {
		t.Error("prompt_injection should be enabled")
	}
	if got := pi.EffectiveBlockThreshold(0.8); got != 0.9 {
		t.Errorf("expected 0.9, got %f", got)
	}

	pii := pc.GetDetectorPolicy("pii")
	if pii.IsEnabled() {
		t.Error("pii should be disabled")
	}
}

func TestParseDetectorConfig_InvalidJSON(t *testing.T) {
	_, err := parseDetectorConfig("not json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// Verify the interface is satisfied at compile time.
var _ Authenticator = (*PostgresAuthenticator)(nil)
var _ ProjectStore = (*sqlProjectStore)(nil)

// Verify engine.PolicyConfig is used (catches import issues).
var _ *engine.PolicyConfig = nil
