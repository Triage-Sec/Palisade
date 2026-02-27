package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/triage-ai/palisade/internal/engine"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// contextKey is an unexported type for context keys to avoid collisions.
type contextKey int

const (
	projectCtxKey contextKey = iota
	policyCtxKey
)

// authProject holds the authenticated project context for a request.
type authProject struct {
	ID       string
	Mode     string
	FailOpen bool
	Policy   *engine.PolicyConfig
}

// projectFromContext extracts the authenticated project from the request context.
func projectFromContext(ctx context.Context) *authProject {
	v, _ := ctx.Value(projectCtxKey).(*authProject)
	return v
}

// --- Auth cache (stale-while-revalidate) ---

type cacheEntry struct {
	project   *authProject
	expiresAt time.Time
	refreshing atomic.Bool
}

type authCache struct {
	store sync.Map // map[string]*cacheEntry (keyed by full API key)
	ttl   time.Duration
}

func newAuthCache(ttl time.Duration) *authCache {
	return &authCache{ttl: ttl}
}

func (c *authCache) get(key string) (proj *authProject, hit bool, needsRefresh bool) {
	v, ok := c.store.Load(key)
	if !ok {
		return nil, false, false
	}
	entry := v.(*cacheEntry)
	if time.Now().Before(entry.expiresAt) {
		return entry.project, true, false // fresh
	}
	// Stale — return value but signal refresh needed (only one goroutine refreshes)
	needsRefresh = entry.refreshing.CompareAndSwap(false, true)
	return entry.project, true, needsRefresh
}

func (c *authCache) set(key string, proj *authProject) {
	c.store.Store(key, &cacheEntry{
		project:   proj,
		expiresAt: time.Now().Add(c.ttl),
	})
}

// --- Auth middleware ---

// authMiddleware returns an http.HandlerFunc that validates Bearer tsk_ tokens
// and injects the authenticated project into the request context.
func (d *Dependencies) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	cache := newAuthCache(d.CacheTTL)

	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := extractBearerToken(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, ErrorResp{Detail: "Missing or invalid Authorization header"})
			return
		}
		if len(token) < 8 || !strings.HasPrefix(token, "tsk_") {
			writeJSON(w, http.StatusUnauthorized, ErrorResp{Detail: "Invalid API key format"})
			return
		}

		// Cache lookup
		proj, hit, needsRefresh := cache.get(token)
		if hit && needsRefresh {
			// Stale hit — return stale immediately, refresh in background
			go d.refreshAuth(cache, token)
		}
		if hit && proj != nil {
			ctx := context.WithValue(r.Context(), projectCtxKey, proj)
			next(w, r.WithContext(ctx))
			return
		}

		// Cache miss — synchronous lookup
		proj, err := d.authenticateToken(r.Context(), token)
		if err != nil {
			d.Logger.Warn("auth failed", zap.Error(err))
			writeJSON(w, http.StatusUnauthorized, ErrorResp{Detail: "Invalid API key"})
			return
		}

		cache.set(token, proj)
		ctx := context.WithValue(r.Context(), projectCtxKey, proj)
		next(w, r.WithContext(ctx))
	}
}

// authenticateToken validates an API key against Postgres and returns the project context.
func (d *Dependencies) authenticateToken(ctx context.Context, token string) (*authProject, error) {
	prefix := token[:8]
	pw, err := d.Store.LookupByPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}
	if pw == nil {
		return nil, fmt.Errorf("project not found for prefix")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(pw.APIKeyHash), []byte(token)); err != nil {
		return nil, err
	}

	policy := parseDetectorConfig(pw.DetectorConfig)

	return &authProject{
		ID:       pw.ID,
		Mode:     pw.Mode,
		FailOpen: pw.FailOpen,
		Policy:   policy,
	}, nil
}

// refreshAuth refreshes the cache entry in the background.
func (d *Dependencies) refreshAuth(cache *authCache, token string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	proj, err := d.authenticateToken(ctx, token)
	if err != nil {
		d.Logger.Warn("background auth refresh failed", zap.Error(err))
		return
	}
	cache.set(token, proj)
}

// parseDetectorConfig converts a JSONB detector_config into engine.PolicyConfig.
func parseDetectorConfig(raw json.RawMessage) *engine.PolicyConfig {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return nil
	}

	var detectors map[string]engine.DetectorPolicy
	if err := json.Unmarshal(raw, &detectors); err != nil {
		return nil
	}
	if len(detectors) == 0 {
		return nil
	}
	return &engine.PolicyConfig{Detectors: detectors}
}

// extractBearerToken extracts the token from "Authorization: Bearer <token>".
func extractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", false
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return "", false
	}
	return strings.TrimSpace(auth[len(prefix):]), true
}

// --- JSON helpers ---

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

// readJSON decodes a JSON request body into the given pointer.
func readJSON(r *http.Request, v interface{}) error {
	defer func() { _ = r.Body.Close() }()
	return json.NewDecoder(r.Body).Decode(v)
}

// --- Request logging ---

func requestLogging(next http.Handler, logger *zap.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		logger.Info("http request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", sw.status),
			zap.Duration("duration", time.Since(start)),
		)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// --- CORS ---

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
