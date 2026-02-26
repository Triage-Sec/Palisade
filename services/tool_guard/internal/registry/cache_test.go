package registry

import (
	"sync"
	"testing"
	"time"
)

func TestCache_FreshHit(t *testing.T) {
	c := NewToolCache(30 * time.Second)
	tool := &ToolDefinition{ToolName: "send_email", RiskTier: "write"}
	c.Set("proj1", "send_email", tool)

	result := c.Get("proj1", "send_email")
	if !result.Hit {
		t.Fatal("expected cache hit")
	}
	if result.NeedsRefresh {
		t.Fatal("expected fresh, got needs refresh")
	}
	if result.Tool.ToolName != "send_email" {
		t.Fatalf("expected send_email, got %s", result.Tool.ToolName)
	}
}

func TestCache_Miss(t *testing.T) {
	c := NewToolCache(30 * time.Second)
	result := c.Get("proj1", "nonexistent")
	if result.Hit {
		t.Fatal("expected miss")
	}
	if result.Tool != nil {
		t.Fatal("expected nil tool on miss")
	}
}

func TestCache_NegativeCache(t *testing.T) {
	c := NewToolCache(30 * time.Second)
	c.Set("proj1", "unknown_tool", nil) // negative cache

	result := c.Get("proj1", "unknown_tool")
	if !result.Hit {
		t.Fatal("expected cache hit for negative cache")
	}
	if result.Tool != nil {
		t.Fatal("expected nil tool for negative cache")
	}
}

func TestCache_StaleHit_ReturnsValueAndSignalsRefresh(t *testing.T) {
	c := NewToolCache(1 * time.Millisecond)
	tool := &ToolDefinition{ToolName: "query_db", RiskTier: "read"}
	c.Set("proj1", "query_db", tool)

	time.Sleep(5 * time.Millisecond)

	result := c.Get("proj1", "query_db")
	if !result.Hit {
		t.Fatal("expected stale hit")
	}
	if !result.NeedsRefresh {
		t.Fatal("expected needs refresh on stale")
	}
	if result.Tool.ToolName != "query_db" {
		t.Fatalf("expected query_db, got %s", result.Tool.ToolName)
	}
}

func TestCache_StaleHit_OnlyOneRefreshSignal(t *testing.T) {
	c := NewToolCache(1 * time.Millisecond)
	tool := &ToolDefinition{ToolName: "query_db", RiskTier: "read"}
	c.Set("proj1", "query_db", tool)

	time.Sleep(5 * time.Millisecond)

	refreshCount := 0
	for i := 0; i < 10; i++ {
		result := c.Get("proj1", "query_db")
		if result.NeedsRefresh {
			refreshCount++
		}
	}
	if refreshCount != 1 {
		t.Fatalf("expected exactly 1 refresh signal, got %d", refreshCount)
	}
}

func TestCache_SetAfterStale_ResetsFreshness(t *testing.T) {
	c := NewToolCache(1 * time.Millisecond)
	tool := &ToolDefinition{ToolName: "query_db", RiskTier: "read"}
	c.Set("proj1", "query_db", tool)

	time.Sleep(5 * time.Millisecond)

	// Re-set refreshes the entry
	updated := &ToolDefinition{ToolName: "query_db", RiskTier: "write"}
	c.Set("proj1", "query_db", updated)

	result := c.Get("proj1", "query_db")
	if !result.Hit {
		t.Fatal("expected hit after re-set")
	}
	if result.NeedsRefresh {
		t.Fatal("expected fresh after re-set")
	}
	if result.Tool.RiskTier != "write" {
		t.Fatalf("expected write tier, got %s", result.Tool.RiskTier)
	}
}

func TestCache_Delete(t *testing.T) {
	c := NewToolCache(30 * time.Second)
	c.Set("proj1", "tool_a", &ToolDefinition{ToolName: "tool_a"})
	c.Delete("proj1", "tool_a")

	result := c.Get("proj1", "tool_a")
	if result.Hit {
		t.Fatal("expected miss after delete")
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	c := NewToolCache(30 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Set("proj1", "tool", &ToolDefinition{ToolName: "tool"})
			c.Get("proj1", "tool")
			c.Delete("proj1", "tool")
		}()
	}
	wg.Wait()
}

func TestCache_ConcurrentStaleRefresh(t *testing.T) {
	c := NewToolCache(1 * time.Millisecond)
	c.Set("proj1", "tool", &ToolDefinition{ToolName: "tool"})

	time.Sleep(5 * time.Millisecond)

	var refreshCount int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := c.Get("proj1", "tool")
			if result.NeedsRefresh {
				mu.Lock()
				refreshCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if refreshCount != 1 {
		t.Fatalf("expected exactly 1 refresh across 50 goroutines, got %d", refreshCount)
	}
}

func BenchmarkToolCache_Get_FreshHit(b *testing.B) {
	c := NewToolCache(30 * time.Second)
	c.Set("proj1", "send_email", &ToolDefinition{ToolName: "send_email"})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Get("proj1", "send_email")
	}
}
