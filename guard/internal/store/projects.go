package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Project represents a row in the projects table.
type Project struct {
	ID             string
	Name           string
	APIKeyHash     string
	APIKeyPrefix   string
	Mode           string // "enforce" or "shadow"
	FailOpen       bool
	ChecksPerMonth *int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ProjectWithPolicy is a Project joined with its Policy (for auth lookups).
type ProjectWithPolicy struct {
	Project
	DetectorConfig  json.RawMessage // from policies.detector_config
	CustomBlocklist json.RawMessage // from policies.custom_blocklist
}

// UpdateProjectParams holds optional fields for partial project updates.
type UpdateProjectParams struct {
	Name           *string
	Mode           *string
	FailOpen       *bool
	ChecksPerMonth *int
}

// GenerateAPIKey creates a new tsk_ API key with its bcrypt hash and prefix.
// Returns (fullKey, hash, prefix, error). The fullKey is shown to the user once.
func GenerateAPIKey() (string, string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", "", fmt.Errorf("GenerateAPIKey: %w", err)
	}
	fullKey := "tsk_" + hex.EncodeToString(raw) // 68 chars total

	hashBytes, err := bcrypt.GenerateFromPassword([]byte(fullKey), bcrypt.DefaultCost)
	if err != nil {
		return "", "", "", fmt.Errorf("GenerateAPIKey: %w", err)
	}

	prefix := fullKey[:8] // "tsk_abcd"
	return fullKey, string(hashBytes), prefix, nil
}

// CreateProject inserts a new project and its default policy in a single transaction.
// Returns the project, policy, and plaintext API key (shown once).
func (s *Store) CreateProject(ctx context.Context, name string) (*Project, *Policy, string, error) {
	fullKey, keyHash, keyPrefix, err := GenerateAPIKey()
	if err != nil {
		return nil, nil, "", fmt.Errorf("CreateProject: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, "", fmt.Errorf("CreateProject: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	var p Project
	err = tx.QueryRowContext(ctx, `
		INSERT INTO projects (name, api_key_hash, api_key_prefix)
		VALUES ($1, $2, $3)
		RETURNING id, name, api_key_hash, api_key_prefix, mode, fail_open,
		          checks_per_month, created_at, updated_at`,
		name, keyHash, keyPrefix,
	).Scan(&p.ID, &p.Name, &p.APIKeyHash, &p.APIKeyPrefix, &p.Mode, &p.FailOpen,
		&p.ChecksPerMonth, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, nil, "", fmt.Errorf("CreateProject: %w", err)
	}

	var pol Policy
	err = tx.QueryRowContext(ctx, `
		INSERT INTO policies (project_id)
		VALUES ($1)
		RETURNING id, project_id, detector_config, COALESCE(custom_blocklist, 'null'::jsonb), created_at, updated_at`,
		p.ID,
	).Scan(&pol.ID, &pol.ProjectID, &pol.DetectorConfig, &pol.CustomBlocklist,
		&pol.CreatedAt, &pol.UpdatedAt)
	if err != nil {
		return nil, nil, "", fmt.Errorf("CreateProject: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, "", fmt.Errorf("CreateProject: %w", err)
	}

	return &p, &pol, fullKey, nil
}

// ListProjects returns all projects ordered by created_at DESC.
func (s *Store) ListProjects(ctx context.Context) ([]*Project, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, api_key_hash, api_key_prefix, mode, fail_open,
		       checks_per_month, created_at, updated_at
		FROM projects ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("ListProjects: %w", err)
	}
	defer rows.Close()

	var projects []*Project
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.Name, &p.APIKeyHash, &p.APIKeyPrefix,
			&p.Mode, &p.FailOpen, &p.ChecksPerMonth, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("ListProjects: %w", err)
		}
		projects = append(projects, &p)
	}
	return projects, rows.Err()
}

// GetProject returns a project by ID, or nil if not found.
func (s *Store) GetProject(ctx context.Context, id string) (*Project, error) {
	var p Project
	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, api_key_hash, api_key_prefix, mode, fail_open,
		       checks_per_month, created_at, updated_at
		FROM projects WHERE id = $1`, id,
	).Scan(&p.ID, &p.Name, &p.APIKeyHash, &p.APIKeyPrefix,
		&p.Mode, &p.FailOpen, &p.ChecksPerMonth, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetProject: %w", err)
	}
	return &p, nil
}

// UpdateProject applies a partial update to a project. Only non-nil fields are changed.
func (s *Store) UpdateProject(ctx context.Context, id string, params UpdateProjectParams) (*Project, error) {
	var p Project
	err := s.db.QueryRowContext(ctx, `
		UPDATE projects SET
			name           = COALESCE($2, name),
			mode           = COALESCE($3, mode),
			fail_open      = COALESCE($4, fail_open),
			checks_per_month = COALESCE($5, checks_per_month),
			updated_at     = now()
		WHERE id = $1
		RETURNING id, name, api_key_hash, api_key_prefix, mode, fail_open,
		          checks_per_month, created_at, updated_at`,
		id, params.Name, params.Mode, params.FailOpen, params.ChecksPerMonth,
	).Scan(&p.ID, &p.Name, &p.APIKeyHash, &p.APIKeyPrefix,
		&p.Mode, &p.FailOpen, &p.ChecksPerMonth, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("UpdateProject: %w", err)
	}
	return &p, nil
}

// DeleteProject deletes a project by ID. The policy cascades.
func (s *Store) DeleteProject(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM projects WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("DeleteProject: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// RotateAPIKey generates a new API key for a project.
// Returns the updated project and the plaintext key (shown once).
func (s *Store) RotateAPIKey(ctx context.Context, id string) (*Project, string, error) {
	fullKey, keyHash, keyPrefix, err := GenerateAPIKey()
	if err != nil {
		return nil, "", fmt.Errorf("RotateAPIKey: %w", err)
	}

	var p Project
	err = s.db.QueryRowContext(ctx, `
		UPDATE projects SET
			api_key_hash   = $2,
			api_key_prefix = $3,
			updated_at     = now()
		WHERE id = $1
		RETURNING id, name, api_key_hash, api_key_prefix, mode, fail_open,
		          checks_per_month, created_at, updated_at`,
		id, keyHash, keyPrefix,
	).Scan(&p.ID, &p.Name, &p.APIKeyHash, &p.APIKeyPrefix,
		&p.Mode, &p.FailOpen, &p.ChecksPerMonth, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, "", fmt.Errorf("RotateAPIKey: project not found")
	}
	if err != nil {
		return nil, "", fmt.Errorf("RotateAPIKey: %w", err)
	}

	return &p, fullKey, nil
}

// LookupByPrefix finds a project by API key prefix (first 8 chars).
// Used by auth to narrow candidates before bcrypt verify.
func (s *Store) LookupByPrefix(ctx context.Context, prefix string) (*ProjectWithPolicy, error) {
	var pw ProjectWithPolicy
	err := s.db.QueryRowContext(ctx, `
		SELECT p.id, p.name, p.api_key_hash, p.api_key_prefix, p.mode, p.fail_open,
		       p.checks_per_month, p.created_at, p.updated_at,
		       COALESCE(pol.detector_config, '{}'),
		       COALESCE(pol.custom_blocklist, 'null'::jsonb)
		FROM projects p
		LEFT JOIN policies pol ON pol.project_id = p.id
		WHERE p.api_key_prefix = $1`, prefix,
	).Scan(&pw.ID, &pw.Name, &pw.APIKeyHash, &pw.APIKeyPrefix,
		&pw.Mode, &pw.FailOpen, &pw.ChecksPerMonth, &pw.CreatedAt, &pw.UpdatedAt,
		&pw.DetectorConfig, &pw.CustomBlocklist)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("LookupByPrefix: %w", err)
	}
	return &pw, nil
}
