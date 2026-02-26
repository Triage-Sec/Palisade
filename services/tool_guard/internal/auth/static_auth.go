package auth

import (
	"context"
)

// StaticAuthenticator is a development-only authenticator that accepts any tsk_ key.
type StaticAuthenticator struct{}

func NewStaticAuthenticator() *StaticAuthenticator {
	return &StaticAuthenticator{}
}

func (a *StaticAuthenticator) Authenticate(ctx context.Context) (*ProjectContext, error) {
	token, err := ExtractBearerToken(ctx)
	if err != nil {
		return nil, err
	}
	// Accept any tsk_ prefixed key with a static project ID
	return &ProjectContext{
		ProjectID: "static-" + token[:8],
		Mode:      "enforce",
		FailOpen:  true,
	}, nil
}
