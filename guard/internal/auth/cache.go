package auth

import (
	"sync"
	"sync/atomic"
	"time"
)

// AuthCache is a TTL-based in-memory cache for authenticated project contexts.
// Uses sync.Map for lock-free reads on the hot path.
//
// Stale-while-revalidate: when an entry expires, Get() still returns the stale
// value immediately (sub-microsecond) and signals that a background refresh is
// needed. This ensures no request ever blocks on DB + bcrypt after the first
// cold start.
type AuthCache struct {
	store sync.Map      // map[string]*cacheEntry
	ttl   time.Duration // Default: 30s
}

type cacheEntry struct {
	project    *ProjectContext
	expiresAt  time.Time
	refreshing atomic.Bool // prevents duplicate background refreshes
}

// NewAuthCache creates a cache with the given TTL.
func NewAuthCache(ttl time.Duration) *AuthCache {
	return &AuthCache{ttl: ttl}
}

// GetResult holds the result of a cache lookup.
type GetResult struct {
	Project    *ProjectContext
	Hit        bool // true if a value was found (fresh or stale)
	NeedsRefresh bool // true if the entry is expired and should be refreshed in the background
}

// Get looks up the API key in the cache.
//
// Returns:
//   - Fresh hit:  {Project, Hit=true,  NeedsRefresh=false}
//   - Stale hit:  {Project, Hit=true,  NeedsRefresh=true}  (serve stale, refresh in background)
//   - Miss:       {nil,     Hit=false, NeedsRefresh=false}
//
// When NeedsRefresh=true, the caller should refresh in a background goroutine.
// The refreshing flag is set atomically so only one goroutine refreshes per key.
func (c *AuthCache) Get(apiKey string) GetResult {
	val, ok := c.store.Load(apiKey)
	if !ok {
		return GetResult{}
	}

	entry := val.(*cacheEntry)

	if time.Now().Before(entry.expiresAt) {
		// Fresh hit — return immediately.
		return GetResult{Project: entry.project, Hit: true}
	}

	// Stale hit — return the value but signal refresh needed.
	// CompareAndSwap ensures only one goroutine triggers the refresh.
	needsRefresh := entry.refreshing.CompareAndSwap(false, true)
	return GetResult{
		Project:      entry.project,
		Hit:          true,
		NeedsRefresh: needsRefresh,
	}
}

// Set stores a project context in the cache with the configured TTL.
func (c *AuthCache) Set(apiKey string, project *ProjectContext) {
	c.store.Store(apiKey, &cacheEntry{
		project:   project,
		expiresAt: time.Now().Add(c.ttl),
	})
}

// Delete removes an entry from the cache.
func (c *AuthCache) Delete(apiKey string) {
	c.store.Delete(apiKey)
}
