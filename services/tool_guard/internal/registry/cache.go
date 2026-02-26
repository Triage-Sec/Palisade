package registry

import (
	"sync"
	"sync/atomic"
	"time"
)

// ToolCache is a TTL-based in-memory cache with stale-while-revalidate for tool definitions.
// Uses sync.Map for lock-free reads on the hot path.
type ToolCache struct {
	store sync.Map // map[string]*toolCacheEntry
	ttl   time.Duration
}

type toolCacheEntry struct {
	tool       *ToolDefinition // nil = negative cache (tool not found)
	expiresAt  time.Time
	refreshing atomic.Bool
}

// CacheGetResult holds the result of a cache lookup.
type CacheGetResult struct {
	Tool         *ToolDefinition // nil if not found or negative cache
	Hit          bool            // true if a value was found (fresh or stale)
	NeedsRefresh bool            // true if expired — caller should refresh in background
}

// NewToolCache creates a cache with the given TTL.
func NewToolCache(ttl time.Duration) *ToolCache {
	return &ToolCache{ttl: ttl}
}

// cacheKey builds the lookup key for a project+tool pair.
func cacheKey(projectID, toolName string) string {
	return projectID + ":" + toolName
}

// Get performs a non-blocking cache lookup.
// Returns stale entries with NeedsRefresh=true when expired.
func (c *ToolCache) Get(projectID, toolName string) CacheGetResult {
	key := cacheKey(projectID, toolName)
	val, ok := c.store.Load(key)
	if !ok {
		return CacheGetResult{Hit: false}
	}

	entry := val.(*toolCacheEntry)
	now := time.Now()

	if now.Before(entry.expiresAt) {
		// Fresh hit
		return CacheGetResult{
			Tool: entry.tool,
			Hit:  true,
		}
	}

	// Stale hit — signal refresh needed (only one goroutine wins the CAS)
	needsRefresh := entry.refreshing.CompareAndSwap(false, true)
	return CacheGetResult{
		Tool:         entry.tool,
		Hit:          true,
		NeedsRefresh: needsRefresh,
	}
}

// Set stores a tool definition in the cache with a fresh TTL.
// Passing nil stores a negative cache entry (tool not found).
func (c *ToolCache) Set(projectID, toolName string, tool *ToolDefinition) {
	key := cacheKey(projectID, toolName)
	c.store.Store(key, &toolCacheEntry{
		tool:      tool,
		expiresAt: time.Now().Add(c.ttl),
	})
}

// Delete removes an entry from the cache.
func (c *ToolCache) Delete(projectID, toolName string) {
	key := cacheKey(projectID, toolName)
	c.store.Delete(key)
}
