package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/triage-ai/palisade/internal/engine"
	"google.golang.org/grpc/metadata"
)

var (
	ErrMissingAPIKey    = errors.New("missing authorization header")
	ErrInvalidAPIKey    = errors.New("invalid API key format")
	ErrMissingProjectID = errors.New("missing x-project-id header")
	ErrAuthUnavailable  = errors.New("auth service unavailable")
)

// ProjectContext holds the authenticated project's configuration.
type ProjectContext struct {
	ProjectID string
	Mode      string              // "enforce" or "shadow"
	FailOpen  bool
	Policy    *engine.PolicyConfig // nil = use server defaults
}

// Authenticator validates incoming requests and returns project context.
type Authenticator interface {
	Authenticate(ctx context.Context) (*ProjectContext, error)
}

// extractAPIKey pulls the Bearer token from gRPC metadata and validates the tsk_ prefix.
// Returns the raw API key (e.g. "tsk_abc123...") or an error.
func extractAPIKey(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrMissingAPIKey
	}

	authValues := md.Get("authorization")
	if len(authValues) == 0 {
		return "", ErrMissingAPIKey
	}

	token := authValues[0]
	// RFC 6750: the "Bearer" scheme is case-insensitive.
	if len(token) > 7 && strings.EqualFold(token[:7], "bearer ") {
		token = token[7:]
	}
	token = strings.TrimSpace(token)

	if !strings.HasPrefix(token, "tsk_") {
		return "", ErrInvalidAPIKey
	}

	return token, nil
}

// extractProjectID pulls the x-project-id from gRPC metadata.
func extractProjectID(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrMissingProjectID
	}

	projectValues := md.Get("x-project-id")
	if len(projectValues) == 0 || projectValues[0] == "" {
		return "", ErrMissingProjectID
	}

	return projectValues[0], nil
}

// StaticAuthenticator is the Phase 1 implementation.
// It validates that the API key starts with "tsk_" and project_id is present.
// No database lookup — just format validation.
type StaticAuthenticator struct{}

func NewStaticAuthenticator() *StaticAuthenticator {
	return &StaticAuthenticator{}
}

func (a *StaticAuthenticator) Authenticate(ctx context.Context) (*ProjectContext, error) {
	if _, err := extractAPIKey(ctx); err != nil {
		return nil, err
	}

	projectID, err := extractProjectID(ctx)
	if err != nil {
		return nil, err
	}

	return &ProjectContext{
		ProjectID: projectID,
		Mode:      "enforce", // Hardcoded for Phase 1
		FailOpen:  true,
	}, nil
}
