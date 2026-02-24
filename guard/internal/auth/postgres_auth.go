package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/triage-ai/palisade/internal/engine"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// ProjectStore abstracts DB queries for testability.
type ProjectStore interface {
	LookupByPrefix(ctx context.Context, prefix string) (*projectRow, error)
}

type projectRow struct {
	ProjectID      string
	APIKeyHash     string
	Mode           string
	FailOpen       bool
	DetectorConfig sql.NullString // JSONB from policies table (NULL if no policy row)
}

// sqlProjectStore is the real implementation using *sql.DB.
type sqlProjectStore struct {
	db *sql.DB
}

func (s *sqlProjectStore) LookupByPrefix(ctx context.Context, prefix string) (*projectRow, error) {
	row := &projectRow{}
	err := s.db.QueryRowContext(ctx,
		`SELECT p.id, p.api_key_hash, p.mode, p.fail_open, pol.detector_config
		 FROM projects p
		 LEFT JOIN policies pol ON pol.project_id = p.id
		 WHERE p.api_key_prefix = $1`,
		prefix,
	).Scan(&row.ProjectID, &row.APIKeyHash, &row.Mode, &row.FailOpen, &row.DetectorConfig)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrInvalidAPIKey // No project with this prefix — reject, don't fail open
		}
		return nil, fmt.Errorf("sqlProjectStore.LookupByPrefix: %w", err)
	}
	return row, nil
}

// PostgresAuthenticator validates API keys against the projects table.
// Uses AuthCache with stale-while-revalidate to avoid DB + bcrypt on the hot path.
// Auth failures always return an error — no detectors run without valid auth.
// The SDK is responsible for fail-open behavior on its side.
type PostgresAuthenticator struct {
	store  ProjectStore
	cache  *AuthCache
	logger *zap.Logger
}

// PostgresAuthConfig configures the PostgresAuthenticator.
type PostgresAuthConfig struct {
	DB       *sql.DB
	CacheTTL time.Duration // Default: 30s
	Logger   *zap.Logger
}

// NewPostgresAuthenticator creates a new authenticator backed by PostgreSQL.
func NewPostgresAuthenticator(cfg PostgresAuthConfig) *PostgresAuthenticator {
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	return &PostgresAuthenticator{
		store:  &sqlProjectStore{db: cfg.DB},
		cache:  NewAuthCache(ttl),
		logger: cfg.Logger,
	}
}

// newPostgresAuthenticatorWithStore creates an authenticator with an injected store (for testing).
func newPostgresAuthenticatorWithStore(store ProjectStore, cache *AuthCache, logger *zap.Logger) *PostgresAuthenticator {
	return &PostgresAuthenticator{
		store:  store,
		cache:  cache,
		logger: logger,
	}
}

// Authenticate validates the API key against the database.
//
// Flow:
//  1. Extract Bearer tsk_... from gRPC metadata
//  2. Cache lookup (stale-while-revalidate):
//     - Fresh hit: return immediately (sub-microsecond)
//     - Stale hit: return stale project, spawn background refresh
//     - Miss: do full DB + bcrypt lookup synchronously
//  3. On DB error with failOpen=true: return degraded ProjectContext
func (a *PostgresAuthenticator) Authenticate(ctx context.Context) (*ProjectContext, error) {
	apiKey, err := extractAPIKey(ctx)
	if err != nil {
		return nil, err
	}

	// 1. Cache lookup
	result := a.cache.Get(apiKey)

	if result.Hit {
		// Stale hit — kick off background refresh, return stale value immediately
		if result.NeedsRefresh {
			go a.backgroundRefresh(apiKey)
		}
		return result.Project, nil
	}

	// 2. Cache miss — do full lookup synchronously
	project, err := a.lookupAndVerify(ctx, apiKey)
	if err != nil {
		return a.handleLookupError(ctx, err)
	}

	a.cache.Set(apiKey, project)
	return project, nil
}

// backgroundRefresh performs the DB + bcrypt lookup in a background goroutine.
// Errors are logged but don't affect the caller (they already got the stale value).
func (a *PostgresAuthenticator) backgroundRefresh(apiKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	project, err := a.lookupAndVerify(ctx, apiKey)
	if err != nil {
		a.logger.Warn("background cache refresh failed",
			zap.Error(err),
		)
		// Don't update cache — stale entry remains. Next stale read will retry.
		// Reset the refreshing flag so the next stale read can try again.
		a.cache.Delete(apiKey)
		return
	}

	a.cache.Set(apiKey, project)
}

// lookupAndVerify does the full DB prefix lookup + bcrypt verification + policy parsing.
func (a *PostgresAuthenticator) lookupAndVerify(ctx context.Context, apiKey string) (*ProjectContext, error) {
	// api_key_prefix is the first 8 chars (e.g. "tsk_abcd")
	if len(apiKey) < 8 {
		return nil, ErrInvalidAPIKey
	}
	prefix := apiKey[:8]

	row, err := a.store.LookupByPrefix(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("lookupAndVerify: %w", err)
	}

	// bcrypt verify
	if err := bcrypt.CompareHashAndPassword([]byte(row.APIKeyHash), []byte(apiKey)); err != nil {
		return nil, ErrInvalidAPIKey
	}

	// Parse policy from detector_config JSONB.
	// The DB stores it as a flat map: {"prompt_injection": {...}, "pii": {...}}
	// not wrapped in a "detectors" key, so we use parseDetectorConfig.
	var policy *engine.PolicyConfig
	if row.DetectorConfig.Valid && row.DetectorConfig.String != "" && row.DetectorConfig.String != "{}" {
		parsed, err := parseDetectorConfig(row.DetectorConfig.String)
		if err != nil {
			a.logger.Warn("failed to parse detector_config, using defaults",
				zap.String("project_id", row.ProjectID),
				zap.Error(err),
			)
			// Don't fail — just use nil policy (server defaults)
		} else {
			policy = parsed
		}
	}

	return &ProjectContext{
		ProjectID: row.ProjectID,
		Mode:      row.Mode,
		FailOpen:  row.FailOpen,
		Policy:    policy,
	}, nil
}

// handleLookupError returns the appropriate error — never runs detectors on auth failure.
func (a *PostgresAuthenticator) handleLookupError(_ context.Context, lookupErr error) (*ProjectContext, error) {
	if errors.Is(lookupErr, ErrInvalidAPIKey) {
		return nil, ErrInvalidAPIKey
	}

	// DB error (timeout, connection refused, etc.) — return unavailable
	a.logger.Warn("auth DB unreachable",
		zap.Error(lookupErr),
	)
	return nil, fmt.Errorf("%w: %v", ErrAuthUnavailable, lookupErr)
}

// parseDetectorConfig parses the detector_config JSON into a PolicyConfig map.
// The DB stores it as {"prompt_injection": {...}, "pii": {...}} — the top level
// IS the detectors map, not wrapped in a "detectors" key.
func parseDetectorConfig(raw string) (*engine.PolicyConfig, error) {
	var detectors map[string]engine.DetectorPolicy
	if err := json.Unmarshal([]byte(raw), &detectors); err != nil {
		return nil, fmt.Errorf("parseDetectorConfig: %w", err)
	}
	return &engine.PolicyConfig{Detectors: detectors}, nil
}
