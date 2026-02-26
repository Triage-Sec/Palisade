package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ToolStore abstracts DB queries for testability.
type ToolStore interface {
	LookupTool(ctx context.Context, projectID, toolName string) (*toolRow, error)
}

type toolRow struct {
	ID                string
	ProjectID         string
	ToolName          string
	Description       sql.NullString
	RiskTier          string
	RequiresConfirm   bool
	Preconditions     string // JSONB as string
	ArgumentSchema    sql.NullString
	ArgumentPolicy    string
	ContextualRules   string
	InformationFlow   string
}

// sqlToolStore is the real implementation using *sql.DB.
type sqlToolStore struct {
	db *sql.DB
}

func (s *sqlToolStore) LookupTool(ctx context.Context, projectID, toolName string) (*toolRow, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, tool_name, description, risk_tier,
		       requires_confirmation, preconditions, argument_schema,
		       argument_policy, contextual_rules, information_flow
		FROM tool_definitions
		WHERE project_id = $1 AND tool_name = $2
	`, projectID, toolName)

	var r toolRow
	if err := row.Scan(
		&r.ID, &r.ProjectID, &r.ToolName, &r.Description, &r.RiskTier,
		&r.RequiresConfirm, &r.Preconditions, &r.ArgumentSchema,
		&r.ArgumentPolicy, &r.ContextualRules, &r.InformationFlow,
	); err != nil {
		return nil, err
	}
	return &r, nil
}

// PostgresToolRegistry fetches tool definitions from the tool_definitions table.
type PostgresToolRegistry struct {
	store    ToolStore
	cache    *ToolCache
	logger   *zap.Logger
}

// PostgresToolRegistryConfig configures the PostgresToolRegistry.
type PostgresToolRegistryConfig struct {
	DB       *sql.DB
	CacheTTL time.Duration
	Logger   *zap.Logger
}

// NewPostgresToolRegistry creates a new PostgresToolRegistry.
func NewPostgresToolRegistry(cfg PostgresToolRegistryConfig) *PostgresToolRegistry {
	ttl := cfg.CacheTTL
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	return &PostgresToolRegistry{
		store:  &sqlToolStore{db: cfg.DB},
		cache:  NewToolCache(ttl),
		logger: cfg.Logger,
	}
}

// newPostgresToolRegistryWithStore creates a registry with a custom store (for testing).
func newPostgresToolRegistryWithStore(store ToolStore, cacheTTL time.Duration, logger *zap.Logger) *PostgresToolRegistry {
	if cacheTTL == 0 {
		cacheTTL = 60 * time.Second
	}
	return &PostgresToolRegistry{
		store:  store,
		cache:  NewToolCache(cacheTTL),
		logger: logger,
	}
}

func (r *PostgresToolRegistry) GetTool(ctx context.Context, projectID, toolName string) (*ToolDefinition, error) {
	// Check cache
	cacheResult := r.cache.Get(projectID, toolName)
	if cacheResult.Hit {
		if cacheResult.NeedsRefresh {
			go r.refreshInBackground(projectID, toolName)
		}
		return cacheResult.Tool, nil
	}

	// Cache miss — fetch from DB
	td, err := r.fetchFromDB(ctx, projectID, toolName)
	if err != nil {
		if err == sql.ErrNoRows {
			// Negative cache: tool not found
			r.cache.Set(projectID, toolName, nil)
			return nil, nil
		}
		return nil, fmt.Errorf("GetTool: %w", err)
	}

	r.cache.Set(projectID, toolName, td)
	return td, nil
}

func (r *PostgresToolRegistry) fetchFromDB(ctx context.Context, projectID, toolName string) (*ToolDefinition, error) {
	row, err := r.store.LookupTool(ctx, projectID, toolName)
	if err != nil {
		return nil, err
	}
	return parseToolRow(row)
}

func (r *PostgresToolRegistry) refreshInBackground(projectID, toolName string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	td, err := r.fetchFromDB(ctx, projectID, toolName)
	if err != nil {
		r.logger.Warn("background tool registry refresh failed",
			zap.String("project_id", projectID),
			zap.String("tool_name", toolName),
			zap.Error(err),
		)
		return
	}
	r.cache.Set(projectID, toolName, td)
}

func parseToolRow(row *toolRow) (*ToolDefinition, error) {
	td := &ToolDefinition{
		ID:              row.ID,
		ProjectID:       row.ProjectID,
		ToolName:        row.ToolName,
		RiskTier:        row.RiskTier,
		RequiresConfirm: row.RequiresConfirm,
	}

	if row.Description.Valid {
		td.Description = row.Description.String
	}

	// Parse preconditions (JSONB array)
	if row.Preconditions != "" && row.Preconditions != "[]" {
		if err := json.Unmarshal([]byte(row.Preconditions), &td.Preconditions); err != nil {
			return nil, fmt.Errorf("parseToolRow: preconditions: %w", err)
		}
	}

	// Parse argument_schema (JSONB object)
	if row.ArgumentSchema.Valid && row.ArgumentSchema.String != "" {
		var schema map[string]any
		if err := json.Unmarshal([]byte(row.ArgumentSchema.String), &schema); err != nil {
			return nil, fmt.Errorf("parseToolRow: argument_schema: %w", err)
		}
		td.ArgumentSchema = schema
	}

	// Parse argument_policy
	if row.ArgumentPolicy != "" && row.ArgumentPolicy != "{}" {
		if err := json.Unmarshal([]byte(row.ArgumentPolicy), &td.ArgumentPolicy); err != nil {
			return nil, fmt.Errorf("parseToolRow: argument_policy: %w", err)
		}
	}

	// Parse contextual_rules
	if row.ContextualRules != "" && row.ContextualRules != "{}" {
		if err := json.Unmarshal([]byte(row.ContextualRules), &td.ContextualRules); err != nil {
			return nil, fmt.Errorf("parseToolRow: contextual_rules: %w", err)
		}
	}

	// Parse information_flow
	if row.InformationFlow != "" && row.InformationFlow != "{}" {
		if err := json.Unmarshal([]byte(row.InformationFlow), &td.InformationFlow); err != nil {
			return nil, fmt.Errorf("parseToolRow: information_flow: %w", err)
		}
	}

	return td, nil
}
