package auth

import (
	"sync"
	"sync/atomic"
	"time"
)

// AuthCache is a TTL-based in-memory cache with stale-while-revalidate.
// Uses sync.Map for lock-free reads on the hot path.
type AuthCache struct {
	store sync.Map // map[string]*cacheEntry
	ttl   time.Duration
}

type cacheEntry struct {
	project    *ProjectContext
	expiresAt  time.Time
	refreshing atomic.Bool
}

// AuthCacheGetResult holds the result of a cache lookup.
type AuthCacheGetResult struct {
	Project      *ProjectContext
	Hit          bool
	NeedsRefresh bool
}

// NewAuthCache creates a cache with the given TTL.
func NewAuthCache(ttl time.Duration) *AuthCache {
	return &AuthCache{ttl: ttl}
}

// Get performs a non-blocking cache lookup.
func (c *AuthCache) Get(apiKey string) AuthCacheGetResult {
	val, ok := c.store.Load(apiKey)
	if !ok {
		return AuthCacheGetResult{Hit: false}
	}

	entry := val.(*cacheEntry)
	now := time.Now()

	if now.Before(entry.expiresAt) {
		return AuthCacheGetResult{
			Project: entry.project,
			Hit:     true,
		}
	}

	needsRefresh := entry.refreshing.CompareAndSwap(false, true)
	return AuthCacheGetResult{
		Project:      entry.project,
		Hit:          true,
		NeedsRefresh: needsRefresh,
	}
}

// Set stores a project context with a fresh TTL.
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
