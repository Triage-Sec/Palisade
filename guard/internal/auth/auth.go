package auth

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/metadata"
)

var (
	ErrMissingAPIKey    = errors.New("missing authorization header")
	ErrInvalidAPIKey    = errors.New("invalid API key format")
	ErrMissingProjectID = errors.New("missing x-project-id header")
)

// ProjectContext holds the authenticated project's configuration.
type ProjectContext struct {
	ProjectID string
	Mode      string // "enforce" or "shadow"
	FailOpen  bool
}

// Authenticator validates incoming requests and returns project context.
type Authenticator interface {
	Authenticate(ctx context.Context) (*ProjectContext, error)
}

// StaticAuthenticator is the Phase 1 implementation.
// It validates that the API key starts with "tsk_" and project_id is present.
// No database lookup — just format validation.
type StaticAuthenticator struct{}

func NewStaticAuthenticator() *StaticAuthenticator {
	return &StaticAuthenticator{}
}

func (a *StaticAuthenticator) Authenticate(ctx context.Context) (*ProjectContext, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, ErrMissingAPIKey
	}

	// Extract authorization header: "Bearer tsk_..."
	authValues := md.Get("authorization")
	if len(authValues) == 0 {
		return nil, ErrMissingAPIKey
	}

	token := authValues[0]
	// RFC 6750: the "Bearer" scheme is case-insensitive.
	if len(token) > 7 && strings.EqualFold(token[:7], "bearer ") {
		token = token[7:]
	}
	token = strings.TrimSpace(token)

	if !strings.HasPrefix(token, "tsk_") {
		return nil, ErrInvalidAPIKey
	}

	// Extract project ID
	projectValues := md.Get("x-project-id")
	if len(projectValues) == 0 || projectValues[0] == "" {
		return nil, ErrMissingProjectID
	}

	return &ProjectContext{
		ProjectID: projectValues[0],
		Mode:      "enforce", // Hardcoded for Phase 1
		FailOpen:  true,
	}, nil
}
