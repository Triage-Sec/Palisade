# CLAUDE.md — Palisade Guard Edge Service

> This file scopes all work to the **Go gRPC Guard Edge Service** (`guard/`).
> This is the enforcement hot path for the entire Triage platform.
> Every architectural decision optimizes for **sub-40ms p99 latency**.

---

## What This Service Does

Palisade is a Go gRPC server that receives `Check` RPCs from SDKs and the Gateway,
runs security detectors against the payload **in parallel**, and returns a
BLOCK / ALLOW / FLAG verdict. It is the single enforcement chokepoint for the
entire Triage AI security firewall.

```
SDK check() ──┐
              ├──► gRPC :50051 ──► Fan-out detectors (parallel) ──► Aggregate ──► CheckResponse
Gateway ──────┘
```

**Non-goals for this service (do NOT build):**
- No HTTP/REST endpoints — gRPC only
- No OTel trace ingestion or span storage
- No dashboard serving — that's the Next.js app
- No Gateway proxy logic — that's `gateway/`
- No SDK code — that's `sdk/`

---

## Project Layout

```
guard/
├── cmd/
│   └── guard-server/
│       └── main.go                     # Entrypoint: gRPC server bootstrap
├── internal/
│   ├── server/
│   │   └── guard_server.go             # GuardService gRPC implementation
│   ├── engine/
│   │   ├── engine.go                   # SentryEngine: policy-aware fan-out detector execution
│   │   ├── detector.go                 # Detector interface definition
│   │   ├── aggregator.go              # Aggregate DetectResults → Verdict (per-detector thresholds)
│   │   ├── defaults.go                 # Default timeout constant
│   │   ├── policy.go                   # PolicyConfig + DetectorPolicy types
│   │   └── detectors/
│   │       ├── prompt_injection.go     # Regex + heuristic patterns
│   │       ├── jailbreak.go            # Pattern matching
│   │       ├── pii.go                  # Regex: SSN, CC, email, phone, IBAN
│   │       ├── content_mod.go          # Keyword + pattern matching
│   │       └── tool_abuse.go           # Blocked functions + SQL/command injection + per-project allow/block lists
│   ├── auth/
│   │   ├── auth.go                     # Authenticator interface, ProjectContext, StaticAuthenticator
│   │   ├── postgres_auth.go            # PostgresAuthenticator — DB-backed auth with cache
│   │   └── cache.go                    # TTL-based sync.Map auth cache (stale-while-revalidate)
│   └── storage/
│       ├── clickhouse.go              # Buffered async ClickHouse writer (fire-and-forget)
│       └── events.go                  # SecurityEvent struct + EventWriter interface
├── gen/
│   └── guard/v1/
│       ├── guard.pb.go                 # Generated
│       └── guard_grpc.pb.go            # Generated
├── deploy/
│   ├── Dockerfile                      # Multi-stage: golang:1.25-alpine → distroless (<20MB)
│   ├── bin/app.ts                      # CDK app entrypoint (dev + prod stacks)
│   ├── lib/guard-stack.ts              # CDK stack: ECS Fargate, NLB, CloudWatch, auto-scaling
│   ├── package.json
│   ├── tsconfig.json
│   └── cdk.json
├── scripts/
│   └── create_docker.sh                # Build + tag + push Docker image to ECR
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

The shared proto lives at the repo root: `proto/guard/v1/guard.proto`.
Generated Go code lands in `guard/gen/guard/v1/`.

---

## Architecture & Hot Path

### Request Flow

```
1. gRPC unary call arrives at GuardService.Check()
2. [Auth] Stale-while-revalidate cache lookup:
   - Fresh HIT (sub-microsecond): return ProjectContext with mode, fail_open, policy
   - Stale HIT (sub-microsecond): return stale ProjectContext immediately,
     kick off background goroutine to refresh (atomic flag prevents duplicates)
   - MISS (~100ms cold path, first request only):
     a. Extract api_key_prefix (first 8 chars of tsk_ key)
     b. SELECT projects JOIN policies WHERE api_key_prefix = $1
     c. bcrypt.CompareHashAndPassword(hash, key)
     d. Parse detector_config JSONB → PolicyConfig
     e. Cache result with 30s TTL
   - DB unreachable + fail_open=true: degrade to ALLOW with warning log
3. [Fan-Out] Policy-filtered detector execution:
   - Skip detectors where policy has enabled=false
   - Launch remaining detectors as goroutines with 25ms deadline
   - Set ToolAllowList/ToolBlockList on DetectRequest for tool_abuse
4. [Collect] Wait for all detectors or context deadline (missed = skipped)
5. [Aggregate] Per-detector thresholds from policy:
   - Each detector's block_threshold/flag_threshold from policy (fallback to server default)
   - ANY detector triggered + confidence >= its block_threshold → BLOCK
   - ANY detector triggered + confidence >= its flag_threshold → FLAG
   - Otherwise → ALLOW
6. [Shadow] If project.Mode == "shadow" and verdict != ALLOW:
   - Log REAL verdict to ClickHouse (for dashboard analytics)
   - Return ALLOW to client, set is_shadow=true
7. [Log] Fire-and-forget: queue security event to ClickHouse (never blocks)
8. Return CheckResponse with verdict + detector results + latency_ms
```

### Performance Invariants

These are non-negotiable constraints. Every code change must preserve them:

- **Total check latency < 40ms p99** (excluding first-request bcrypt cold start)
- **Detector fan-out timeout: 25ms** — detectors that don't finish are skipped
- **Zero heap allocations on the hot path where possible** — reuse buffers, pre-compile regexes
- **No blocking I/O on the hot path** — logging/storage is always async fire-and-forget
- **No mutex contention on check path** — use `sync.Map` for cache, channels for detector output
- **gRPC keepalive: 30s ping** — persistent connections
- **Auth cache hit is sub-microsecond** — `sync.Map.Load()` is lock-free for reads (45ns benchmarked)
- **No auth latency spikes** — stale-while-revalidate serves expired entries immediately, refreshes in background

### Pre-compiled Regex Rule

All regex patterns MUST be compiled at init time using `regexp.MustCompile` as package-level
variables. **Never compile regex inside a request handler.**

---

## Configuration (Environment Variables)

| Var | Default | Description |
|-----|---------|-------------|
| `GUARD_PORT` | `50051` | gRPC listen port |
| `GUARD_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `GUARD_DETECTOR_TIMEOUT_MS` | `25` | Max time for detector fan-out |
| `GUARD_BLOCK_THRESHOLD` | `0.8` | Global confidence threshold for BLOCK verdict |
| `GUARD_FLAG_THRESHOLD` | `0.0` | Global confidence threshold for FLAG verdict |
| `CLICKHOUSE_DSN` | `` | ClickHouse connection string (empty = log events to stdout) |
| `POSTGRES_DSN` | `` | PostgreSQL connection string (empty = use StaticAuthenticator) |
| `GUARD_AUTH_CACHE_TTL_S` | `30` | Auth cache TTL in seconds |

---

## Build & Run

```bash
# Generate proto
make proto

# Build
cd guard && go build -o bin/guard-server ./cmd/guard-server/

# Run locally (no Postgres = StaticAuthenticator fallback)
./bin/guard-server

# Run locally with Postgres
POSTGRES_DSN="postgres://user:pass@localhost:5432/triage?sslmode=require" ./bin/guard-server

# Run tests
cd guard && go test ./... -v

# Run tests with race detector
cd guard && go test ./... -v -race

# Run benchmarks
cd guard && go test -bench=. -benchmem ./...

# Docker build (from repo root)
docker build -f guard/deploy/Dockerfile -t palisade-guard .
```

---

## CI/CD & Deployment

### Overview

```
Developer pushes PR   → guard-ci.yml (lint → test → Docker build smoke test)
PR merges to main     → (no deploy — just CI validation)
git tag guard-dev@*   → guard-deploy.yml → Docker → ECR → CDK → ECS (dev)
git tag guard-prod@*  → guard-deploy.yml → Docker → ECR → CDK → ECS (prod, requires approval)
```

### GitHub Actions Workflows

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `guard-ci.yml` | Push to `main`, PRs (path-filtered to `guard/**`, `proto/**`) | Lint (golangci-lint v2.10) → Test (`go test -race`) → Docker build smoke test |
| `guard-deploy.yml` | Tags `guard-dev@*` or `guard-prod@*` | Build Docker → Push to ECR → CDK deploy to ECS Fargate |

### How to Deploy

```bash
# Deploy to dev (auto-deploys, no approval needed):
git tag guard-dev@0.2.0
git push origin guard-dev@0.2.0

# Deploy to prod (requires manual approval in GitHub):
git tag guard-prod@0.2.0
git push origin guard-prod@0.2.0
```

### GitHub Environments & Secrets

**Environments** (configured in GitHub repo settings):

| Environment | Protection Rules | Used by |
|-------------|-----------------|---------|
| `Guard Dev` | None (auto-deploy) | `guard-dev@*` tags |
| `Guard Prod` | Required reviewers | `guard-prod@*` tags |

**Secrets** (set per environment):

| Secret | Description |
|--------|-------------|
| `AWS_ACCOUNT_ID` | AWS account ID |
| `AWS_ACCESS_KEY_ID` | IAM user access key for ECR push + ECS deploy |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret key |
| `CLICKHOUSE_DSN` | ClickHouse connection string |
| `POSTGRES_DSN` | Supabase PostgreSQL connection string |
| `VPC_ID` | VPC ID to deploy into (shared with backend) |

### Infrastructure (CDK)

CDK stack at `guard/deploy/` provisions per environment:

| Resource | Details |
|----------|---------|
| ECS Cluster | `palisade-guard-{env}` — Fargate |
| ECS Fargate Service | 2 tasks min, 0.5 vCPU / 1GB, circuit breaker auto-rollback |
| NLB | Internet-facing, TCP on port 50051 (required for gRPC — ALB breaks HTTP/2) |
| Security Group | Inbound TCP 50051 |
| CloudWatch Logs | `/ecs/palisade-guard-{env}`, 30-day retention |
| Auto-scaling | 2→10 tasks, target 70% CPU |

ECR repo `palisade-guard` is created by `scripts/create_docker.sh` (CDK looks it up, does not create it).

Tasks run in **public subnets** with `assignPublicIp: true` to reach ClickHouse Cloud without a NAT Gateway.

### Dockerfile

Multi-stage build at `guard/deploy/Dockerfile`. Build context is repo root.

```
Builder:  golang:1.25-alpine → go mod download → go build (static, CGO_ENABLED=0)
Runtime:  gcr.io/distroless/static-debian12:nonroot (<20MB, no shell)
Port:     50051
```

### Monitoring

```bash
# View logs
aws logs tail /ecs/palisade-guard-dev --follow

# Check service status
aws ecs describe-services --cluster palisade-guard-dev --services palisade-guard-dev
```

---

## Code Style & Conventions

- **No global state except pre-compiled regexes.** Pass dependencies via constructor injection.
- **All detector patterns are `var` blocks at package level** — compiled once, used forever.
- **Use `context.Context` everywhere.** Respect deadlines. Never ignore cancellation.
- **Errors wrap with `fmt.Errorf("functionName: %w", err)`** for stack traceability.
- **Structured logging only** — `zap.Logger`, never `fmt.Println` or `log.Printf`.
- **No `init()` functions.** Explicit initialization in `main()` or constructors.
- **Test files live next to the code they test.** No separate `test/` directory.
- **Interfaces are defined where they're consumed**, not where they're implemented.
- **Keep dependencies minimal.** No ORMs, no HTTP frameworks, no config libraries.
- **Atomic operations over mutexes** on the hot path. Use `sync.Map` for read-heavy caches.

---

## Current State

### Phase 1 — Guard Core (DONE, deployed to dev)

- [x] Proto definition + code generation
- [x] Guard gRPC server with health checks + graceful shutdown
- [x] 5 regex/heuristic detectors (prompt injection, jailbreak, PII, content mod, tool abuse)
- [x] SentryEngine with parallel fan-out + 25ms deadline
- [x] Aggregator (hardcoded thresholds: 0.8 block, 0.0 flag)
- [x] StaticAuthenticator (tsk_ prefix check, hardcoded mode/fail_open)
- [x] ClickHouse buffered async writer + LogWriter fallback
- [x] CI pipeline (lint + test + Docker smoke test)
- [x] Deploy pipeline (tag-based, ECR + CDK + ECS Fargate)
- [x] CDK infrastructure (ECS, NLB, CloudWatch, auto-scaling)

### Phase 2 — Backend + HTTP API (DONE, 281 tests passing)

- [x] PostgreSQL tables: `projects` + `policies` (Drizzle schema + migration)
- [x] `POST /v1/palisade` — HTTP payload screening endpoint
- [x] `tsk_` API key auth: bcrypt hash + prefix-indexed lookup
- [x] Project CRUD: create, list, get, update, delete, rotate key
- [x] Policy CRUD: get, partial update, full replace
- [x] ClickHouse read path: events listing, single event, analytics
- [x] gRPC client: backend → Guard edge service (fail-open, timeout)

---

## Phase 3 — Guard Upgrades (DONE, 93 tests passing)

**Goal:** Connect Guard to the real database. Make `projects` and `policies` tables
actually drive Guard behavior. Without this, the product doesn't work end-to-end —
the backend writes config but Guard ignores it.

### PostgreSQL Tables (already exist in Supabase, created by backend)

```sql
-- projects table (source of truth: parse/packages/db/src/schema/projects.ts)
CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    api_key_hash    TEXT NOT NULL,                   -- bcrypt(tsk_<64 hex chars>)
    api_key_prefix  TEXT NOT NULL,                   -- first 8 chars: "tsk_abcd" (indexed)
    mode            TEXT NOT NULL DEFAULT 'shadow',  -- "enforce" | "shadow"
    fail_open       BOOLEAN NOT NULL DEFAULT true,
    checks_per_month INTEGER DEFAULT 100000,
    created_at      TIMESTAMP DEFAULT now(),
    updated_at      TIMESTAMP DEFAULT now()
);

-- policies table (source of truth: parse/packages/db/src/schema/policies.ts)
-- 1:1 with projects, auto-created when project is created
CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID REFERENCES projects(id) ON DELETE CASCADE NOT NULL,
    detector_config JSONB NOT NULL DEFAULT '{}',     -- per-detector settings
    custom_blocklist JSONB,
    created_at      TIMESTAMP DEFAULT now(),
    updated_at      TIMESTAMP DEFAULT now()
);
```

**Policy `detector_config` format:**

```json
{
    "prompt_injection": {
        "enabled": true,
        "block_threshold": 0.9,
        "flag_threshold": 0.0
    },
    "pii": {
        "enabled": false
    },
    "tool_abuse": {
        "enabled": true,
        "allowed_tools": ["search", "calculator"],
        "blocked_tools": ["exec", "eval"]
    }
}
```

Keys = detector names. Omitted detectors use server defaults (enabled, block=0.8, flag=0.0).

---

### Step 1: PolicyConfig Types (DONE)

**File:** `guard/internal/engine/policy.go`

```go
// PolicyConfig represents per-project detector configuration.
// Loaded from the policies table's detector_config JSONB column.
type PolicyConfig struct {
    Detectors map[string]DetectorPolicy
}

// DetectorPolicy controls behavior of a single detector for a project.
type DetectorPolicy struct {
    Enabled        *bool    `json:"enabled"`         // nil = use server default (true)
    BlockThreshold *float32 `json:"block_threshold"` // nil = use server default (0.8)
    FlagThreshold  *float32 `json:"flag_threshold"`  // nil = use server default (0.0)
    AllowedTools   []string `json:"allowed_tools"`   // tool_abuse only
    BlockedTools   []string `json:"blocked_tools"`   // tool_abuse only
}

func (dp DetectorPolicy) IsEnabled() bool                                     // nil → true
func (dp DetectorPolicy) EffectiveBlockThreshold(serverDefault float32) float32 // nil → serverDefault
func (dp DetectorPolicy) EffectiveFlagThreshold(serverDefault float32) float32  // nil → serverDefault

// GetDetectorPolicy returns the policy for a detector. Missing = zero value (all defaults).
func (pc *PolicyConfig) GetDetectorPolicy(detectorName string) DetectorPolicy  // nil-safe
```

**Tests:** `guard/internal/engine/policy_test.go`
- Nil PolicyConfig returns defaults
- Missing detector returns defaults
- Explicit `enabled: false` returns false
- Custom thresholds override server defaults

---

### Step 2: Engine + Aggregator Policy Awareness (DONE)

**Modify:** `guard/internal/engine/engine.go`

```go
// Evaluate gains policy param (nil = run all detectors with server defaults)
func (e *SentryEngine) Evaluate(
    ctx context.Context,
    req *DetectRequest,
    policy *PolicyConfig,
) ([]*guardv1.DetectorResult, time.Duration)
```

**`Evaluate()` changes:**
1. Filter detectors: skip if `policy.GetDetectorPolicy(name).IsEnabled() == false`
2. For `tool_abuse` detector: copy `DetectRequest` and set `ToolAllowList`/`ToolBlockList` from policy
3. Rest of fan-out + collection logic unchanged

**Modify:** `guard/internal/engine/detector.go`

```go
type DetectRequest struct {
    Payload       string
    Action        guardv1.ActionType
    ToolCall      *guardv1.ToolCall
    ToolAllowList []string  // NEW: per-project tool allowlist (set by engine)
    ToolBlockList []string  // NEW: per-project tool blocklist (set by engine)
}
```

**Modify:** `guard/internal/engine/detectors/tool_abuse.go`

In `Detect()`, **before** the global `blockedFunctionNames` check:
1. If `req.ToolAllowList` is non-empty and tool function is NOT in the list → trigger (0.90, "tool not in project allowlist")
2. If tool function is in `req.ToolBlockList` → trigger (0.95, "tool in project blocklist")
3. Then proceed with existing global blocklist + injection pattern checks

**Modify:** `guard/internal/engine/aggregator.go`

Add new function alongside existing `Aggregate()`:

```go
// AggregateWithPolicy applies per-detector thresholds from the policy.
// Falls back to server defaults for detectors without custom thresholds.
func AggregateWithPolicy(
    results []*guardv1.DetectorResult,
    defaultCfg AggregatorConfig,
    policy *PolicyConfig,
) AggregateResult
```

For each triggered detector result:
- Look up `policy.GetDetectorPolicy(result.Detector)`
- Use `dp.EffectiveBlockThreshold(defaultCfg.BlockThreshold)` instead of global threshold
- Use `dp.EffectiveFlagThreshold(defaultCfg.FlagThreshold)` instead of global threshold

Keep existing `Aggregate()` unchanged — it calls `AggregateWithPolicy(results, cfg, nil)`.

---

### Step 3: Auth Cache (DONE)

**File:** `guard/internal/auth/cache.go`

```go
// AuthCache is a TTL-based in-memory cache with stale-while-revalidate.
// Uses sync.Map for lock-free reads on the hot path.
type AuthCache struct {
    store sync.Map       // map[string]*cacheEntry
    ttl   time.Duration  // Default: 30s
}

type cacheEntry struct {
    project    *ProjectContext
    expiresAt  time.Time
    refreshing atomic.Bool  // prevents duplicate background refreshes
}

// GetResult holds the result of a cache lookup.
type GetResult struct {
    Project      *ProjectContext
    Hit          bool  // true if a value was found (fresh or stale)
    NeedsRefresh bool  // true if expired — caller should refresh in background
}

func NewAuthCache(ttl time.Duration) *AuthCache
func (c *AuthCache) Get(apiKey string) GetResult   // never blocks, returns stale on expiry
func (c *AuthCache) Set(apiKey string, project *ProjectContext)
func (c *AuthCache) Delete(apiKey string)
```

**Design:**
- `sync.Map` — lock-free reads (read-heavy, write-rare pattern)
- **Stale-while-revalidate**: expired entries are returned immediately with `NeedsRefresh=true`.
  The caller spawns a background goroutine to refresh. `atomic.Bool` CompareAndSwap ensures
  exactly one goroutine refreshes per key — other readers get the stale value and move on.
- No background goroutine for cleanup — stale entries serve until refreshed
- Memory bounded by number of active API keys (projects)
- **Benchmarked: 45ns/op, 0 allocs** on fresh hit

**Tests:** `guard/internal/auth/cache_test.go`
- `TestCache_FreshHit`, `TestCache_Miss`
- `TestCache_StaleHit_ReturnsValueAndSignalsRefresh`
- `TestCache_StaleHit_OnlyOneRefreshSignal` (atomic dedup)
- `TestCache_SetAfterStale_ResetsFreshness`
- `TestCache_Delete`
- `TestCache_ConcurrentAccess` (race detector, 100 goroutines)
- `TestCache_ConcurrentStaleRefresh` (50 goroutines, exactly 1 refresh)
- `BenchmarkCache_Get_FreshHit` (must be sub-microsecond)

---

### Step 4: PostgresAuthenticator (DONE)

**File:** `guard/internal/auth/postgres_auth.go`

```go
// ProjectStore abstracts DB queries for testability.
type ProjectStore interface {
    LookupByPrefix(ctx context.Context, prefix string) (*projectRow, error)
}

type projectRow struct {
    ProjectID       string
    APIKeyHash      string
    Mode            string
    FailOpen        bool
    DetectorConfig  sql.NullString  // JSONB from policies table
}

// sqlProjectStore is the real implementation using *sql.DB.
type sqlProjectStore struct {
    db *sql.DB
}

func (s *sqlProjectStore) LookupByPrefix(ctx context.Context, prefix string) (*projectRow, error)
// Executes: SELECT p.id, p.api_key_hash, p.mode, p.fail_open, pol.detector_config
//           FROM projects p LEFT JOIN policies pol ON pol.project_id = p.id
//           WHERE p.api_key_prefix = $1

// PostgresAuthenticator validates API keys against the projects table.
type PostgresAuthenticator struct {
    store    ProjectStore
    cache    *AuthCache
    logger   *zap.Logger
    failOpen bool
}

type PostgresAuthConfig struct {
    DB       *sql.DB
    CacheTTL time.Duration  // Default: 30s
    FailOpen bool           // Default: true
    Logger   *zap.Logger
}

func NewPostgresAuthenticator(cfg PostgresAuthConfig) *PostgresAuthenticator
func (a *PostgresAuthenticator) Authenticate(ctx context.Context) (*ProjectContext, error)
```

**`Authenticate()` flow:**
1. Extract `Bearer tsk_...` from gRPC metadata (same as StaticAuthenticator)
2. `cache.Get(fullKey)` → returns `GetResult{Project, Hit, NeedsRefresh}`
   - **Fresh hit** (`Hit=true, NeedsRefresh=false`): return immediately (sub-microsecond)
   - **Stale hit** (`Hit=true, NeedsRefresh=true`): return stale project immediately,
     spawn background goroutine to do steps 3-6 and call `cache.Set()`
   - **Miss** (`Hit=false`): do steps 3-6 synchronously (~100ms, first request only)
3. `store.LookupByPrefix(ctx, key[:8])` → get `projectRow`
4. `bcrypt.CompareHashAndPassword(hash, key)` → ~100ms
5. Parse `DetectorConfig` JSON → `*engine.PolicyConfig`
6. `cache.Set(fullKey, projectContext)` — cache for TTL
7. Return `ProjectContext{ProjectID, Mode, FailOpen, Policy}`
8. If DB error + `failOpen=true`: return degraded `ProjectContext` (mode=enforce, policy=nil, project_id from x-project-id header)

**Modify:** `guard/internal/auth/auth.go`

Add `Policy` field to `ProjectContext`:

```go
type ProjectContext struct {
    ProjectID string
    Mode      string                  // "enforce" or "shadow"
    FailOpen  bool
    Policy    *engine.PolicyConfig    // NEW: nil = use server defaults
}
```

**Tests:** `guard/internal/auth/postgres_auth_test.go`
- Use mock `ProjectStore` (no real DB needed)
- `TestPostgresAuth_CacheHit` — prime cache, verify no DB call
- `TestPostgresAuth_CacheMiss_ValidKey` — mock returns row, bcrypt verifies
- `TestPostgresAuth_CacheMiss_InvalidKey` — bcrypt fails → error
- `TestPostgresAuth_ProjectNotFound` — `sql.ErrNoRows` → error
- `TestPostgresAuth_DBDown_FailOpen` — store returns error → fallback ALLOW
- `TestPostgresAuth_DBDown_FailClosed` — store returns error → error
- `TestPostgresAuth_PolicyParsing` — JSON policy parsed correctly

---

### Step 5: main.go Wiring (DONE)

**Modify:** `guard/cmd/guard-server/main.go`

```go
import (
    // ... existing imports ...
    "context"
    "database/sql"
    _ "github.com/jackc/pgx/v5/stdlib"  // Register pgx as database/sql driver
)

func main() {
    // ... existing logger + config ...
    postgresDSN := os.Getenv("POSTGRES_DSN")
    cacheTTL := envOrDefaultInt("GUARD_AUTH_CACHE_TTL_S", 30)

    // Detectors (unchanged)
    dets := []engine.Detector{ ... }

    // Engine (unchanged constructor)
    eng := engine.NewSentryEngine(dets, detectorTimeout, logger)

    // Auth — Postgres if DSN provided, otherwise static (backward compatible)
    var authenticator auth.Authenticator
    if postgresDSN != "" {
        db, err := sql.Open("pgx", postgresDSN)
        if err != nil {
            logger.Fatal("failed to open postgres", zap.Error(err))
        }
        defer db.Close()
        db.SetMaxOpenConns(10)
        db.SetMaxIdleConns(5)
        db.SetConnMaxLifetime(5 * time.Minute)
        if err := db.PingContext(context.Background()); err != nil {
            logger.Fatal("failed to ping postgres", zap.Error(err))
        }
        authenticator = auth.NewPostgresAuthenticator(auth.PostgresAuthConfig{
            DB:       db,
            CacheTTL: time.Duration(cacheTTL) * time.Second,
            FailOpen: true,
            Logger:   logger,
        })
        logger.Info("postgres authenticator connected")
    } else {
        authenticator = auth.NewStaticAuthenticator()
        logger.Info("using static authenticator (no POSTGRES_DSN)")
    }

    // ... rest unchanged (storage, gRPC server, etc.) ...
}
```

**Modify:** `guard/internal/server/guard_server.go`

In `Check()`:
```go
// Fan-out to detectors — pass project policy
detectorResults, _ := s.engine.Evaluate(ctx, detectReq, project.Policy)

// Aggregate with per-detector thresholds
aggResult := engine.AggregateWithPolicy(detectorResults, s.aggCfg, project.Policy)
```

**Modify:** `guard/internal/server/guard_server_test.go`

All existing tests pass unchanged because:
- `StaticAuthenticator` returns `Policy: nil`
- `Evaluate(ctx, req, nil)` runs all detectors with server defaults
- `AggregateWithPolicy(results, cfg, nil)` uses global thresholds

---

### Step 6: Deploy Changes (DONE)

**Modify:** `guard/deploy/lib/guard-stack.ts`

Add `POSTGRES_DSN` to container environment:
```typescript
const postgresDsn = process.env.POSTGRES_DSN || "";

environment: {
    // ... existing vars ...
    POSTGRES_DSN: postgresDsn,
},
```

**Modify:** `.github/workflows/guard-deploy.yml`

Add `POSTGRES_DSN` secret to both dev and prod deploy steps:
```yaml
env:
  # ... existing ...
  POSTGRES_DSN: ${{ secrets.POSTGRES_DSN }}
```

Pass in CDK deploy command:
```bash
VERSION="$VERSION" CLICKHOUSE_DSN="${{ env.CLICKHOUSE_DSN }}" \
  POSTGRES_DSN="${{ env.POSTGRES_DSN }}" VPC_ID="${{ env.VPC_ID }}" \
  npx cdk deploy ...
```

**Modify:** `guard/go.mod`

```bash
cd guard && go get github.com/jackc/pgx/v5 golang.org/x/crypto
```

---

### Dependencies (go.mod after Phase 3)

```
google.golang.org/grpc                   # gRPC server
google.golang.org/protobuf               # Protobuf runtime
go.uber.org/zap                          # Structured logging
github.com/ClickHouse/clickhouse-go/v2   # ClickHouse client
github.com/google/uuid                   # UUID generation
github.com/jackc/pgx/v5                  # PostgreSQL driver (NEW)
golang.org/x/crypto                      # bcrypt (NEW)
```

---

### Build Order

Each step is a self-contained, testable commit:

1. ~~**PolicyConfig types** — pure addition, no existing files changed~~ ✅ DONE
2. ~~**Engine + aggregator policy awareness** — modifies engine, aggregator, detector, tool_abuse; updates guard_server and tests~~ ✅ DONE
3. ~~**Auth cache** — stale-while-revalidate, sync.Map, atomic dedup~~ ✅ DONE
4. ~~**PostgresAuthenticator** — uses cache `GetResult` API, creates postgres_auth.go~~ ✅ DONE
5. ~~**main.go wiring** — conditional Postgres init, new env vars~~ ✅ DONE
6. ~~**Deploy changes** — CDK + workflow + go.mod~~ ✅ DONE

---

### Verification

```bash
# All tests must pass
cd guard && go test ./... -v -race

# Benchmarks — cache must be sub-microsecond on hot path
cd guard && go test -bench=. -benchmem ./...

# Docker build smoke test
docker build -f guard/deploy/Dockerfile -t palisade-guard .
```

**End-to-end (after deploy):**
- [ ] `POST /v1/palisade` with real `tsk_` key → Guard authenticates against Postgres
- [ ] Change project mode to "shadow" via PATCH → Guard returns `is_shadow=true`
- [ ] Disable a detector in policy → Guard skips it, doesn't appear in response
- [ ] Set custom `block_threshold=0.95` → only high-confidence detections trigger BLOCK
- [ ] Invalid API key → Guard returns UNAUTHENTICATED (not hardcoded ALLOW)
- [ ] Kill Postgres → Guard returns fail-open ALLOW (with warning log)

---

## Future Phases

### Phase 4: SDKs — Python + TypeScript

| Item | Description | Where |
|------|-------------|-------|
| Python SDK | gRPC client with `check()`, circuit breaker, fail-open, lazy connection | `triage-sdk-python/` |
| TypeScript SDK | Same pattern as Python SDK | `triage-sdk-typescript/` |

### Phase 5: Dashboard

| Item | Description | Where |
|------|-------------|-------|
| Security events table | Paginated table from ClickHouse | `parse/apps/web/` |
| Threat analytics | Charts: blocks over time, top categories, top users | `parse/apps/web/` |
| Policy editor | Mode toggle, detector config, sensitivity sliders | `parse/apps/web/` |
| Project settings | Creation, API key display, rotation | `parse/apps/web/` |

### Phase 6: TLS, Advanced Detectors, Circuit Breakers, Integrations

| Item | Description | Where |
|------|-------------|-------|
| TLS on NLB | Add TLS termination at the NLB (ACM certificate required) | `guard/deploy/lib/guard-stack.ts` |
| Per-detector circuit breakers | Auto-disable failing detectors (relevant when ML detectors make network calls) | `guard/internal/circuit/` |
| ML-based detectors | Replace regex heuristics with trained classifiers | `guard/internal/engine/detectors/` |
| Custom rules engine | Per-project regex/keyword rules from database | `guard/internal/engine/detectors/` |
| CheckBatch RPC | Server-streaming batch checks | `guard/`, `sdk/` |
| LangChain callback | `TriageGuardCallback` | `triage-sdk-python/` |
| Vercel AI hook | `triageGuard()` middleware | `triage-sdk-typescript/` |
