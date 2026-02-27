package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Policy represents a row in the policies table.
type Policy struct {
	ID              string
	ProjectID       string
	DetectorConfig  json.RawMessage // JSONB — raw bytes
	CustomBlocklist json.RawMessage // nullable JSONB
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// UpdatePolicyParams holds optional fields for partial policy updates.
type UpdatePolicyParams struct {
	DetectorConfig  *json.RawMessage // nil = don't change
	CustomBlocklist *json.RawMessage // nil = don't change
}

// ReplacePolicyParams holds fields for a full policy replace.
type ReplacePolicyParams struct {
	DetectorConfig  json.RawMessage
	CustomBlocklist json.RawMessage // may be nil
}

// GetPolicy returns the policy for a project, or nil if not found.
func (s *Store) GetPolicy(ctx context.Context, projectID string) (*Policy, error) {
	var p Policy
	err := s.db.QueryRowContext(ctx, `
		SELECT id, project_id, detector_config, COALESCE(custom_blocklist, 'null'::jsonb), created_at, updated_at
		FROM policies WHERE project_id = $1`, projectID,
	).Scan(&p.ID, &p.ProjectID, &p.DetectorConfig, &p.CustomBlocklist,
		&p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("GetPolicy: %w", err)
	}
	return &p, nil
}

// UpdatePolicy applies a partial update to a policy. Only non-nil fields are changed.
func (s *Store) UpdatePolicy(ctx context.Context, projectID string, params UpdatePolicyParams) (*Policy, error) {
	var p Policy
	err := s.db.QueryRowContext(ctx, `
		UPDATE policies SET
			detector_config  = COALESCE($2, detector_config),
			custom_blocklist = COALESCE($3, custom_blocklist),
			updated_at       = now()
		WHERE project_id = $1
		RETURNING id, project_id, detector_config, COALESCE(custom_blocklist, 'null'::jsonb), created_at, updated_at`,
		projectID, nullableJSON(params.DetectorConfig), nullableJSON(params.CustomBlocklist),
	).Scan(&p.ID, &p.ProjectID, &p.DetectorConfig, &p.CustomBlocklist,
		&p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("UpdatePolicy: %w", err)
	}
	return &p, nil
}

// ReplacePolicy fully replaces a policy's configuration.
func (s *Store) ReplacePolicy(ctx context.Context, projectID string, params ReplacePolicyParams) (*Policy, error) {
	dc := params.DetectorConfig
	if dc == nil {
		dc = json.RawMessage(`{}`)
	}

	var p Policy
	err := s.db.QueryRowContext(ctx, `
		UPDATE policies SET
			detector_config  = $2,
			custom_blocklist = $3,
			updated_at       = now()
		WHERE project_id = $1
		RETURNING id, project_id, detector_config, COALESCE(custom_blocklist, 'null'::jsonb), created_at, updated_at`,
		projectID, dc, nullableRaw(params.CustomBlocklist),
	).Scan(&p.ID, &p.ProjectID, &p.DetectorConfig, &p.CustomBlocklist,
		&p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ReplacePolicy: %w", err)
	}
	return &p, nil
}

// nullableJSON returns nil (SQL NULL) if the pointer is nil, otherwise the raw bytes.
func nullableJSON(v *json.RawMessage) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

// nullableRaw returns nil (SQL NULL) if the raw message is nil or empty.
func nullableRaw(v json.RawMessage) interface{} {
	if v == nil {
		return nil
	}
	return v
}
