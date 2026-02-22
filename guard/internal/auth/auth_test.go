package auth

import (
	"context"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestStaticAuthenticator_ValidRequest(t *testing.T) {
	a := NewStaticAuthenticator()

	md := metadata.Pairs(
		"authorization", "Bearer tsk_abc123",
		"x-project-id", "proj_test",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	project, err := a.Authenticate(ctx)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if project.ProjectID != "proj_test" {
		t.Errorf("expected project_id 'proj_test', got '%s'", project.ProjectID)
	}
	if project.Mode != "enforce" {
		t.Errorf("expected mode 'enforce', got '%s'", project.Mode)
	}
	if !project.FailOpen {
		t.Error("expected fail_open=true")
	}
}

func TestStaticAuthenticator_MissingAuthHeader(t *testing.T) {
	a := NewStaticAuthenticator()

	md := metadata.Pairs("x-project-id", "proj_test")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := a.Authenticate(ctx)
	if err != ErrMissingAPIKey {
		t.Errorf("expected ErrMissingAPIKey, got: %v", err)
	}
}

func TestStaticAuthenticator_NoMetadata(t *testing.T) {
	a := NewStaticAuthenticator()

	_, err := a.Authenticate(context.Background())
	if err != ErrMissingAPIKey {
		t.Errorf("expected ErrMissingAPIKey, got: %v", err)
	}
}

func TestStaticAuthenticator_InvalidKeyPrefix(t *testing.T) {
	a := NewStaticAuthenticator()

	tests := []struct {
		name  string
		token string
	}{
		{"wrong prefix", "Bearer bad_abc123"},
		{"no prefix", "Bearer abc123"},
		{"empty after Bearer", "Bearer "},
		{"just Bearer", "Bearer"},
		{"sk_ prefix", "Bearer sk_abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := metadata.Pairs(
				"authorization", tt.token,
				"x-project-id", "proj_test",
			)
			ctx := metadata.NewIncomingContext(context.Background(), md)

			_, err := a.Authenticate(ctx)
			if err != ErrInvalidAPIKey {
				t.Errorf("expected ErrInvalidAPIKey for token '%s', got: %v", tt.token, err)
			}
		})
	}
}

func TestStaticAuthenticator_MissingProjectID(t *testing.T) {
	a := NewStaticAuthenticator()

	md := metadata.Pairs("authorization", "Bearer tsk_abc123")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := a.Authenticate(ctx)
	if err != ErrMissingProjectID {
		t.Errorf("expected ErrMissingProjectID, got: %v", err)
	}
}

func TestStaticAuthenticator_EmptyProjectID(t *testing.T) {
	a := NewStaticAuthenticator()

	md := metadata.Pairs(
		"authorization", "Bearer tsk_abc123",
		"x-project-id", "",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := a.Authenticate(ctx)
	if err != ErrMissingProjectID {
		t.Errorf("expected ErrMissingProjectID for empty project ID, got: %v", err)
	}
}

func TestStaticAuthenticator_LowercaseBearer(t *testing.T) {
	a := NewStaticAuthenticator()

	md := metadata.Pairs(
		"authorization", "bearer tsk_abc123",
		"x-project-id", "proj_test",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	project, err := a.Authenticate(ctx)
	if err != nil {
		t.Fatalf("expected no error for lowercase bearer, got: %v", err)
	}
	if project.ProjectID != "proj_test" {
		t.Errorf("expected project_id 'proj_test', got '%s'", project.ProjectID)
	}
}

func TestStaticAuthenticator_TokenWithWhitespace(t *testing.T) {
	a := NewStaticAuthenticator()

	md := metadata.Pairs(
		"authorization", "Bearer  tsk_abc123 ",
		"x-project-id", "proj_test",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	project, err := a.Authenticate(ctx)
	if err != nil {
		t.Fatalf("expected no error for token with extra whitespace, got: %v", err)
	}
	if project.ProjectID != "proj_test" {
		t.Errorf("expected project_id 'proj_test', got '%s'", project.ProjectID)
	}
}

func BenchmarkStaticAuthenticator(b *testing.B) {
	a := NewStaticAuthenticator()
	md := metadata.Pairs(
		"authorization", "Bearer tsk_abc123",
		"x-project-id", "proj_test",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		a.Authenticate(ctx)
	}
}
