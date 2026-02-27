package api

import (
	"net/http"
	"time"

	"github.com/triage-ai/palisade/internal/chread"
	"github.com/triage-ai/palisade/internal/engine"
	"github.com/triage-ai/palisade/internal/storage"
	"github.com/triage-ai/palisade/internal/store"
	"go.uber.org/zap"
)

// Dependencies holds shared state injected into all HTTP handlers.
type Dependencies struct {
	Store    *store.Store
	Engine   *engine.SentryEngine
	Writer   storage.EventWriter
	Reader   *chread.Reader // nil if ClickHouse unavailable
	AggCfg   engine.AggregatorConfig
	Logger   *zap.Logger
	CacheTTL time.Duration
}

// NewRouter builds the HTTP mux with all routes wired up.
func NewRouter(deps *Dependencies) http.Handler {
	mux := http.NewServeMux()

	// Check endpoint (auth required via Bearer tsk_ token)
	mux.HandleFunc("POST /v1/palisade", deps.authMiddleware(deps.handleCheck))

	// Project CRUD (no auth — dashboard auth added later)
	mux.HandleFunc("POST /api/palisade/projects", deps.handleCreateProject)
	mux.HandleFunc("GET /api/palisade/projects", deps.handleListProjects)
	mux.HandleFunc("GET /api/palisade/projects/{project_id}", deps.handleGetProject)
	mux.HandleFunc("PATCH /api/palisade/projects/{project_id}", deps.handleUpdateProject)
	mux.HandleFunc("DELETE /api/palisade/projects/{project_id}", deps.handleDeleteProject)
	mux.HandleFunc("POST /api/palisade/projects/{project_id}/rotate-key", deps.handleRotateKey)

	// Policy CRUD (no auth)
	mux.HandleFunc("GET /api/palisade/projects/{project_id}/policy", deps.handleGetPolicy)
	mux.HandleFunc("PUT /api/palisade/projects/{project_id}/policy", deps.handleReplacePolicy)
	mux.HandleFunc("PATCH /api/palisade/projects/{project_id}/policy", deps.handleUpdatePolicy)

	// Events & Analytics (no auth)
	mux.HandleFunc("GET /api/palisade/events", deps.handleListEvents)
	mux.HandleFunc("GET /api/palisade/events/{request_id}", deps.handleGetEvent)
	mux.HandleFunc("GET /api/palisade/analytics", deps.handleGetAnalytics)

	// Health check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	return corsMiddleware(requestLogging(mux, deps.Logger))
}
