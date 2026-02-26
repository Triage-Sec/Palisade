package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// ProjectStore abstracts DB queries for testability.
type ProjectStore interface {
	LookupByPrefix(ctx context.Context, prefix string) (*projectRow, error)
}

type projectRow struct {
	ProjectID  string
	APIKeyHash string
	Mode       string
	FailOpen   bool
}

// sqlProjectStore is the real implementation using *sql.DB.
type sqlProjectStore struct {
	db *sql.DB
}

func (s *sqlProjectStore) LookupByPrefix(ctx context.Context, prefix string) (*projectRow, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, api_key_hash, mode, fail_open
		FROM projects
		WHERE api_key_prefix = $1
	`, prefix)

	var r projectRow
	if err := row.Scan(&r.ProjectID, &r.APIKeyHash, &r.Mode, &r.FailOpen); err != nil {
		return nil, err
	}
	return &r, nil
}

// PostgresAuthenticator validates API keys against the projects table.
type PostgresAuthenticator struct {
	store    ProjectStore
	cache    *AuthCache
	logger   *zap.Logger
	failOpen bool
}

// PostgresAuthConfig configures the PostgresAuthenticator.
type PostgresAuthConfig struct {
	DB       *sql.DB
	CacheTTL time.Duration
	FailOpen bool
	Logger   *zap.Logger
}

// NewPostgresAuthenticator creates a new PostgresAuthenticator.
func NewPostgresAuthenticator(cfg PostgresAuthConfig) *PostgresAuthenticator {
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = 30 * time.Second
	}
	return &PostgresAuthenticator{
		store:    &sqlProjectStore{db: cfg.DB},
		cache:    NewAuthCache(ttl),
		logger:   cfg.Logger,
		failOpen: cfg.FailOpen,
	}
}

// NewPostgresAuthenticatorWithStore creates an authenticator with a custom store (for testing).
func NewPostgresAuthenticatorWithStore(store ProjectStore, cacheTTL time.Duration, failOpen bool, logger *zap.Logger) *PostgresAuthenticator {
	if cacheTTL == 0 {
		cacheTTL = 30 * time.Second
	}
	return &PostgresAuthenticator{
		store:    store,
		cache:    NewAuthCache(cacheTTL),
		logger:   logger,
		failOpen: failOpen,
	}
}

func (a *PostgresAuthenticator) Authenticate(ctx context.Context) (*ProjectContext, error) {
	token, err := ExtractBearerToken(ctx)
	if err != nil {
		return nil, err
	}

	// Check cache
	cacheResult := a.cache.Get(token)
	if cacheResult.Hit {
		if cacheResult.NeedsRefresh {
			go a.refreshInBackground(token)
		}
		return cacheResult.Project, nil
	}

	// Cache miss — authenticate synchronously
	project, err := a.authenticateFromDB(ctx, token)
	if err != nil {
		if a.failOpen {
			a.logger.Warn("auth failed, degrading to fail-open",
				zap.Error(err),
			)
			return &ProjectContext{
				ProjectID: "unknown",
				Mode:      "enforce",
				FailOpen:  true,
			}, nil
		}
		return nil, fmt.Errorf("Authenticate: %w", err)
	}

	a.cache.Set(token, project)
	return project, nil
}

func (a *PostgresAuthenticator) authenticateFromDB(ctx context.Context, token string) (*ProjectContext, error) {
	if len(token) < 8 {
		return nil, ErrUnauthenticated
	}
	prefix := token[:8]

	row, err := a.store.LookupByPrefix(ctx, prefix)
	if err != nil {
		return nil, fmt.Errorf("authenticateFromDB: %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(row.APIKeyHash), []byte(token)); err != nil {
		return nil, ErrUnauthenticated
	}

	return &ProjectContext{
		ProjectID: row.ProjectID,
		Mode:      row.Mode,
		FailOpen:  row.FailOpen,
	}, nil
}

func (a *PostgresAuthenticator) refreshInBackground(token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	project, err := a.authenticateFromDB(ctx, token)
	if err != nil {
		a.logger.Warn("background auth refresh failed", zap.Error(err))
		return
	}
	a.cache.Set(token, project)
}
