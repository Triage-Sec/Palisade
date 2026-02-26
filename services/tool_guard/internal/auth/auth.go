package auth

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc/metadata"
)

// Authenticator validates incoming requests and returns a ProjectContext.
type Authenticator interface {
	Authenticate(ctx context.Context) (*ProjectContext, error)
}

// ProjectContext holds the authenticated project's identity and configuration.
type ProjectContext struct {
	ProjectID string
	Mode      string // "enforce" or "shadow"
	FailOpen  bool
}

// ErrUnauthenticated is returned when no valid credentials are found.
var ErrUnauthenticated = errors.New("unauthenticated")

// ExtractBearerToken extracts a tsk_ API key from gRPC metadata.
func ExtractBearerToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", ErrUnauthenticated
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return "", ErrUnauthenticated
	}
	token := values[0]
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	if !strings.HasPrefix(token, "tsk_") {
		return "", ErrUnauthenticated
	}
	return token, nil
}
