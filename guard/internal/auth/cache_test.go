package auth

import (
	"sync"
	"testing"
	"time"
)

func TestCache_FreshHit(t *testing.T) {
	cache := NewAuthCache(1 * time.Minute)
	project := &ProjectContext{ProjectID: "proj_1", Mode: "enforce", FailOpen: true}

	cache.Set("tsk_abc123", project)

	result := cache.Get("tsk_abc123")
	if !result.Hit {
		t.Fatal("expected cache hit")
	}
	if result.NeedsRefresh {
		t.Error("fresh entry should not need refresh")
	}
	if result.Project.ProjectID != "proj_1" {
		t.Errorf("expected proj_1, got %s", result.Project.ProjectID)
	}
}

func TestCache_Miss(t *testing.T) {
	cache := NewAuthCache(1 * time.Minute)

	result := cache.Get("tsk_nonexistent")
	if result.Hit {
		t.Error("expected cache miss")
	}
	if result.Project != nil {
		t.Error("expected nil project on miss")
	}
	if result.NeedsRefresh {
		t.Error("miss should not need refresh")
	}
}

func TestCache_StaleHit_ReturnsValueAndSignalsRefresh(t *testing.T) {
	cache := NewAuthCache(1 * time.Millisecond) // Very short TTL
	project := &ProjectContext{ProjectID: "proj_1", Mode: "shadow"}

	cache.Set("tsk_abc123", project)
	time.Sleep(5 * time.Millisecond) // Wait for expiration

	result := cache.Get("tsk_abc123")
	if !result.Hit {
		t.Fatal("expected stale hit")
	}
	if !result.NeedsRefresh {
		t.Error("expired entry should signal refresh")
	}
	if result.Project.ProjectID != "proj_1" {
		t.Error("stale hit should still return the project")
	}
}

func TestCache_StaleHit_OnlyOneRefreshSignal(t *testing.T) {
	cache := NewAuthCache(1 * time.Millisecond)
	cache.Set("tsk_abc123", &ProjectContext{ProjectID: "proj_1"})
	time.Sleep(5 * time.Millisecond)

	// First stale read gets NeedsRefresh=true
	r1 := cache.Get("tsk_abc123")
	if !r1.NeedsRefresh {
		t.Fatal("first stale read should signal refresh")
	}

	// Second stale read gets NeedsRefresh=false (someone already refreshing)
	r2 := cache.Get("tsk_abc123")
	if !r2.Hit {
		t.Fatal("expected stale hit on second read")
	}
	if r2.NeedsRefresh {
		t.Error("second stale read should NOT signal refresh (already in progress)")
	}
	if r2.Project.ProjectID != "proj_1" {
		t.Error("second stale read should still return the project")
	}
}

func TestCache_SetAfterStale_ResetsFreshness(t *testing.T) {
	cache := NewAuthCache(1 * time.Millisecond)
	cache.Set("tsk_abc123", &ProjectContext{ProjectID: "proj_1"})
	time.Sleep(5 * time.Millisecond)

	// Trigger stale read
	r1 := cache.Get("tsk_abc123")
	if !r1.NeedsRefresh {
		t.Fatal("expected refresh signal")
	}

	// Simulate background refresh completing with updated data
	cache.Set("tsk_abc123", &ProjectContext{ProjectID: "proj_1_updated", Mode: "shadow"})

	// Now should be fresh again
	r2 := cache.Get("tsk_abc123")
	if !r2.Hit {
		t.Fatal("expected hit after refresh")
	}
	if r2.NeedsRefresh {
		t.Error("newly set entry should be fresh")
	}
	if r2.Project.ProjectID != "proj_1_updated" {
		t.Errorf("expected updated project, got %s", r2.Project.ProjectID)
	}
}

func TestCache_Delete(t *testing.T) {
	cache := NewAuthCache(1 * time.Minute)
	cache.Set("tsk_abc123", &ProjectContext{ProjectID: "proj_1"})

	cache.Delete("tsk_abc123")

	result := cache.Get("tsk_abc123")
	if result.Hit {
		t.Error("expected miss after delete")
	}
}

func TestCache_ConcurrentAccess(t *testing.T) {
	cache := NewAuthCache(50 * time.Millisecond)
	project := &ProjectContext{ProjectID: "proj_concurrent", Mode: "enforce"}

	var wg sync.WaitGroup
	// Hammer the cache from 100 goroutines simultaneously
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cache.Set("tsk_key", project)
			result := cache.Get("tsk_key")
			if !result.Hit {
				t.Error("expected hit during concurrent access")
			}
			if result.Project.ProjectID != "proj_concurrent" {
				t.Error("unexpected project ID during concurrent access")
			}
		}()
	}
	wg.Wait()
}

func TestCache_ConcurrentStaleRefresh(t *testing.T) {
	cache := NewAuthCache(1 * time.Millisecond)
	cache.Set("tsk_key", &ProjectContext{ProjectID: "proj_1"})
	time.Sleep(5 * time.Millisecond) // Expire

	// 50 goroutines all read the stale entry — exactly one should get NeedsRefresh=true
	var wg sync.WaitGroup
	var refreshCount int64
	var mu sync.Mutex

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := cache.Get("tsk_key")
			if result.NeedsRefresh {
				mu.Lock()
				refreshCount++
				mu.Unlock()
			}
			if !result.Hit {
				t.Error("expected stale hit")
			}
		}()
	}
	wg.Wait()

	if refreshCount != 1 {
		t.Errorf("expected exactly 1 refresh signal, got %d", refreshCount)
	}
}

func BenchmarkCache_Get_FreshHit(b *testing.B) {
	cache := NewAuthCache(5 * time.Minute)
	cache.Set("tsk_bench_key", &ProjectContext{
		ProjectID: "proj_bench",
		Mode:      "enforce",
		FailOpen:  true,
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result := cache.Get("tsk_bench_key")
			if !result.Hit {
				b.Fatal("expected hit")
			}
		}
	})
}
