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
│   │   ├── engine.go                   # SentryEngine: fan-out detector execution
│   │   ├── detector.go                 # Detector interface definition
│   │   ├── aggregator.go              # Aggregate DetectResults → Verdict
│   │   ├── defaults.go                 # Hardcoded thresholds + detector registry
│   │   └── detectors/
│   │       ├── prompt_injection.go     # Regex + heuristic patterns
│   │       ├── jailbreak.go            # Pattern matching
│   │       ├── pii.go                  # Regex: SSN, CC, email, phone, IBAN
│   │       ├── content_mod.go          # Keyword + pattern matching
│   │       └── tool_abuse.go           # Hardcoded allowed-list + argument validation
│   ├── auth/
│   │   └── auth.go                     # API key validation (hardcoded for now)
│   ├── storage/
│   │   ├── clickhouse.go              # Buffered async ClickHouse writer (fire-and-forget)
│   │   └── events.go                  # SecurityEvent struct + EventWriter interface
│   └── circuit/
│       └── breaker.go                  # Per-detector circuit breakers
├── proto/
│   └── guard/v1/
│       └── guard.proto                 # Protobuf definition (symlink or copy from root proto/)
├── gen/
│   └── guard/v1/
│       ├── guard.pb.go                 # Generated
│       └── guard_grpc.pb.go            # Generated
├── deploy/
│   └── Dockerfile
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

The shared proto lives at the repo root: `proto/guard/v1/guard.proto`.
Generated Go code lands in `guard/gen/guard/v1/`.

---

## Architecture & Hot Path

### Request Flow (every `check()` call)

```
1. gRPC unary call arrives at GuardService.Check()
2. [Auth] Validate API key from gRPC metadata
   - For now: accept any key prefixed with "tsk_" (hardcoded)
   - Later: hash-lookup against projects table in Postgres
3. [Fan-Out] Launch ALL registered detectors as goroutines
   - Each detector gets a context with 25ms deadline
   - All run concurrently via errgroup or raw goroutines + channel
4. [Collect] Wait for all detectors or context deadline
   - Detectors that miss the deadline → treated as not-triggered
5. [Aggregate] Apply hardcoded threshold rules:
   - ANY detector confidence >= 0.8 → BLOCK
   - ANY detector triggered but confidence < 0.8 → FLAG
   - All clear → ALLOW
6. [Log] Fire-and-forget: queue security event to ClickHouse buffered writer (never blocks)
7. Return CheckResponse with verdict + detector results + latency_ms
```

### Performance Invariants

These are non-negotiable constraints. Every code change must preserve them:

- **Total check latency < 40ms p99** (including network, auth, detection, aggregation)
- **Detector fan-out timeout: 25ms** — detectors that don't finish are skipped
- **Zero heap allocations on the hot path where possible** — reuse buffers, pre-compile regexes
- **No blocking I/O on the hot path** — logging/storage is always async fire-and-forget
- **No mutex contention on check path** — use channels or atomic operations
- **gRPC keepalive: 30s ping** — persistent connections, no per-request TLS handshake

### Pre-compiled Regex Rule

All regex patterns in detectors MUST be compiled at init time using `regexp.MustCompile`
and stored as package-level variables or struct fields. **Never compile regex inside a
request handler.**

```go
// CORRECT — compiled once at startup
var promptInjectionPatterns = []*regexp.Regexp{
    regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous\s+instructions`),
    regexp.MustCompile(`(?i)you\s+are\s+now\s+`),
}

// WRONG — compiled per request, kills latency
func (d *PromptInjectionDetector) Detect(ctx context.Context, req *DetectRequest) (*DetectResult, error) {
    re := regexp.MustCompile(`(?i)ignore previous instructions`) // DO NOT DO THIS
}
```

---

## Proto Definition

The proto file at `proto/guard/v1/guard.proto` defines the contract between SDKs/Gateway and this service. See IMPLEMENTATION.md Part 2 (lines 394-534) for the full schema. Key points:

- **Package:** `triage.guard.v1`
- **Go package:** `github.com/triage-ai/palisade/gen/guard/v1;guardv1`
- **Service:** `GuardService` with `Check(CheckRequest) returns (CheckResponse)`
- **`CheckBatchRequest`** exists in proto but is **not implemented yet** (Phase 3)

### Proto Generation

```bash
# From repo root
protoc \
  --go_out=guard/gen --go_opt=paths=source_relative \
  --go-grpc_out=guard/gen --go-grpc_opt=paths=source_relative \
  proto/guard/v1/guard.proto
```

Required tools: `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`.

Install:
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

---

## Detector Interface

Every detector implements this interface:

```go
type Detector interface {
    Name() string
    Category() guardv1.ThreatCategory
    Detect(ctx context.Context, req *DetectRequest) (*DetectResult, error)
}

type DetectRequest struct {
    Payload  string
    Action   guardv1.ActionType
    ToolCall *guardv1.ToolCall // nil unless action == TOOL_CALL
}

type DetectResult struct {
    Triggered  bool
    Confidence float32 // 0.0 – 1.0
    Details    string
}
```

### Phase 1 Detectors (Regex/Heuristic Only)

These detectors use **hardcoded regex patterns only**. No ML models, no external API calls.
They must complete well within the 25ms detector deadline.

| Detector | What it catches | Approach |
|----------|----------------|----------|
| `prompt_injection` | "ignore previous instructions", system prompt override attempts, delimiter injection | ~15-25 regex patterns, case-insensitive |
| `jailbreak` | DAN prompts, roleplay jailbreaks, encoding tricks | ~10-20 regex patterns for known jailbreak templates |
| `pii` | SSN, credit card numbers, email addresses, phone numbers, IBAN | Targeted regex per PII type, high precision |
| `content_mod` | Explicit violence, hate speech keywords, self-harm | Keyword lists + simple pattern matching |
| `tool_abuse` | Dangerous function names (exec, eval, rm, DROP), SQL injection patterns in tool args | Hardcoded blocklist + SQL injection regex |

### Writing a New Detector

1. Create `guard/internal/engine/detectors/<name>.go`
2. Implement the `Detector` interface
3. Pre-compile all regex patterns as package-level vars
4. Register in `guard/internal/engine/defaults.go`
5. Write tests in `guard/internal/engine/detectors/<name>_test.go`

---

## Aggregation Rules (Hardcoded — Phase 1)

In `guard/internal/engine/aggregator.go`:

```
Input: []DetectorResult from all detectors that completed within deadline

Rules (applied in order):
1. If ANY detector has Triggered=true AND Confidence >= 0.8 → verdict = BLOCK
2. If ANY detector has Triggered=true AND Confidence < 0.8  → verdict = FLAG
3. Otherwise → verdict = ALLOW

Additional:
- If project mode = "shadow" → override final verdict to ALLOW, set is_shadow=true
  (For now, mode is always "enforce" since we're not reading from Postgres yet)
- Reason string = comma-joined names of all triggered detectors
```

No per-project policies, no per-detector thresholds, no custom rules. That's Phase 3.

---

## Auth (Phase 1 — Hardcoded)

For initial testing, auth is minimal:

- Extract `authorization` header from gRPC metadata → expect `Bearer tsk_...`
- Extract `x-project-id` header from gRPC metadata
- Validate: key starts with `tsk_`, project_id is non-empty → pass
- **No database lookup yet.** No hash verification. Just prefix check.
- Later (Phase 2): hash the API key, look up in Postgres `projects` table

The auth layer must be structured so swapping in real DB-backed auth is a single
implementation change (interface-based).

```go
type Authenticator interface {
    Authenticate(ctx context.Context) (*ProjectContext, error)
}

type ProjectContext struct {
    ProjectID string
    Mode      string // "enforce" or "shadow"
    FailOpen  bool
}
```

Phase 1 implementation: `StaticAuthenticator` that always returns enforce mode.
Phase 2 implementation: `PostgresAuthenticator` that queries the projects table.

---

## Storage — ClickHouse Security Events Writer

Every `check()` call produces a security event that gets written to ClickHouse.
This is how the dashboard sees what's being blocked/flagged. But storage **never**
touches the hot path — it's fully async fire-and-forget.

### Interface

```go
// storage/events.go
type EventWriter interface {
    Write(event *SecurityEvent)  // Non-blocking. Drops on full buffer.
    Close()                      // Drain buffer, flush remaining, close connection.
}

type SecurityEvent struct {
    RequestID          string
    ProjectID          string
    Timestamp          time.Time
    Action             string
    PayloadPreview     string    // First 500 chars
    PayloadHash        string    // SHA256 of full payload
    PayloadSize        uint32
    Verdict            string
    IsShadow           bool
    Reason             string
    DetectorNames      []string
    DetectorTriggered  []bool
    DetectorConfidences []float32
    DetectorCategories []string
    DetectorDetails    []string
    UserID             string
    SessionID          string
    TenantID           string
    ClientTraceID      string
    ToolName           string
    ToolArguments      string
    Metadata           map[string]string
    LatencyMs          float32
    Source             string    // "sdk" or "gateway"
    SDKLanguage        string
    SDKVersion         string
}
```

### ClickHouseWriter Implementation

```go
// storage/clickhouse.go
type ClickHouseWriter struct {
    conn    clickhouse.Conn
    buffer  chan *SecurityEvent  // Buffered channel, capacity 10,000
    done    chan struct{}
}
```

**Critical design rules:**

1. **`Write()` is a non-blocking channel send.** If buffer is full, drop the event
   and increment a dropped-events counter. NEVER block the caller.
   ```go
   func (w *ClickHouseWriter) Write(event *SecurityEvent) {
       select {
       case w.buffer <- event:
       default:
           // Buffer full — drop event, never block the hot path
       }
   }
   ```

2. **Background flush loop** runs in a separate goroutine. Batch-inserts every
   100ms or when 1000 events accumulate, whichever comes first.

3. **`Close()`** signals the flush loop to drain remaining events and shut down.
   Called during graceful server shutdown. Max drain time: 2 seconds.

4. **Connection failure is silent.** If ClickHouse is down, events are dropped.
   The guard service continues returning verdicts. Storage is best-effort.

### ClickHouse Table

See IMPLEMENTATION.md Part 4 (lines 722-791) for the full `security_events` DDL.
The writer must match that schema exactly.

### Local Development

For local dev without a ClickHouse instance, provide a `LogWriter` fallback that
logs events to stdout as structured JSON (via zap). Controlled by env var:
- `CLICKHOUSE_DSN` set → use `ClickHouseWriter`
- `CLICKHOUSE_DSN` empty → use `LogWriter` (prints events to stdout)

---

## gRPC Server Configuration

```go
// In cmd/guard-server/main.go
server := grpc.NewServer(
    grpc.KeepaliveParams(keepalive.ServerParameters{
        MaxConnectionIdle:     5 * time.Minute,
        MaxConnectionAge:      30 * time.Minute,
        MaxConnectionAgeGrace: 10 * time.Second,
        Time:                  30 * time.Second,  // Keepalive ping interval
        Timeout:               5 * time.Second,
    }),
    grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
        MinTime:             10 * time.Second,
        PermitWithoutStream: true,
    }),
    grpc.MaxRecvMsgSize(4 * 1024 * 1024),  // 4MB max message
    grpc.MaxSendMsgSize(4 * 1024 * 1024),
)
```

**Listen on:** `:50051` (configurable via `GUARD_PORT` env var)

### Health Check

Implement gRPC health checking protocol (`grpc.health.v1.Health`) for ECS task health checks.

---

## Configuration (Environment Variables)

| Var | Default | Description |
|-----|---------|-------------|
| `GUARD_PORT` | `50051` | gRPC listen port |
| `GUARD_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `GUARD_DETECTOR_TIMEOUT_MS` | `25` | Max time for detector fan-out |
| `GUARD_BLOCK_THRESHOLD` | `0.8` | Confidence threshold for BLOCK verdict |
| `GUARD_FLAG_THRESHOLD` | `0.0` | Confidence threshold for FLAG verdict (any triggered) |
| `GUARD_TLS_CERT` | `` | Path to TLS cert (empty = plaintext for local dev) |
| `GUARD_TLS_KEY` | `` | Path to TLS key |

| `CLICKHOUSE_DSN` | `` | ClickHouse connection string (empty = log events to stdout) |

Phase 2 additions (not yet):
| `POSTGRES_DSN` | — | PostgreSQL connection string for projects table |

---

## Testing Strategy

### Unit Tests

Every detector gets its own `_test.go` with:
- Known-malicious inputs that MUST trigger (true positives)
- Known-safe inputs that MUST NOT trigger (true negatives)
- Edge cases: unicode, mixed case, whitespace variations, partial matches
- Benchmark tests (`func BenchmarkDetector`) — must complete in <1ms per call

### Integration Tests

- Spin up the gRPC server in-process
- Send CheckRequests with various payloads
- Assert correct verdict, detector results, latency_ms populated
- Test auth rejection (missing key, wrong prefix)
- Test deadline enforcement (inject a slow detector, verify it's skipped)

### Benchmark Tests

```bash
cd guard && go test -bench=. -benchmem ./internal/engine/...
```

Every detector benchmark must show **zero allocations per operation** for the regex
matching path (pre-compiled patterns) and complete in microseconds, not milliseconds.

---

## Build & Run

```bash
# Generate proto
make proto

# Build
cd guard && go build -o bin/guard-server ./cmd/guard-server/

# Run locally
./bin/guard-server

# Run tests
cd guard && go test ./... -v

# Run benchmarks
cd guard && go test -bench=. -benchmem ./...

# Docker build
docker build -f guard/deploy/Dockerfile -t palisade-guard .
```

### Makefile Targets

The top-level `guard/Makefile` should have:
- `proto` — regenerate proto stubs
- `build` — compile the binary
- `test` — run all tests
- `bench` — run benchmarks
- `lint` — run golangci-lint
- `docker` — build Docker image
- `run` — build and run locally

---

## Dependencies (go.mod)

Keep dependencies minimal. Every dependency adds build time and attack surface.

```
google.golang.org/grpc                   # gRPC server + client
google.golang.org/protobuf               # Protobuf runtime
go.uber.org/zap                          # Structured logging (fast, zero-alloc)
github.com/ClickHouse/clickhouse-go/v2   # ClickHouse client (async batch writer)
github.com/google/uuid                   # UUID generation for request_id
```

That's it for Phase 1. No ORMs, no HTTP frameworks, no config libraries.

Phase 2 additions:
```
github.com/jackc/pgx/v5                  # PostgreSQL client (project auth)
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

The guard service follows the same tag-based deploy pattern as the backend.
CI runs on every push/PR. Deploys are triggered by git tags only.

### GitHub Actions Workflows

| Workflow | Trigger | What it does |
|----------|---------|-------------|
| `guard-ci.yml` | Push to `main`, PRs (path-filtered to `guard/**`, `proto/**`) | Lint (golangci-lint) → Test (`go test -race`) → Docker build smoke test |
| `guard-deploy.yml` | Tags `guard-dev@*` or `guard-prod@*` | Build Docker → Push to ECR → CDK deploy to ECS Fargate |

### How to Deploy

```bash
# Deploy to dev (auto-deploys, no approval needed):
git tag guard-dev@0.1.0
git push origin guard-dev@0.1.0

# Deploy to prod (requires manual approval in GitHub):
git tag guard-prod@0.1.0
git push origin guard-prod@0.1.0
```

The version in the tag (e.g. `0.1.0`) becomes the Docker image tag in ECR.

### GitHub Environments & Secrets

**Environments** (configured in GitHub repo settings → Environments):

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
| `CLICKHOUSE_DSN` | ClickHouse connection string for the guard service |

### Infrastructure (CDK)

The CDK stack lives in `guard/deploy/` and provisions:

```
guard/deploy/
├── bin/app.ts             # CDK app entrypoint (dev + prod stacks)
├── lib/guard-stack.ts     # Stack: ECR, ECS Fargate, NLB, CloudWatch
├── package.json           # CDK TypeScript dependencies
├── tsconfig.json
└── cdk.json
```

**What CDK creates per environment:**

| Resource | Details |
|----------|---------|
| ECR Repository | `palisade-guard` — stores Docker images (20 image lifecycle) |
| ECS Cluster | `palisade-guard-{env}` — Fargate cluster |
| ECS Fargate Service | 2 tasks min, 0.5 vCPU / 1GB each, rolling deploy with auto-rollback |
| NLB | Internet-facing, TCP on port 50051 — required for gRPC (ALB breaks HTTP/2) |
| Security Group | Inbound TCP 50051 |
| CloudWatch Logs | `/ecs/palisade-guard-{env}`, 30-day retention |
| Auto-scaling | 2→10 tasks, target 70% CPU utilization |

**First-time setup (before first deploy):**

1. Set `VPC_ID` in `guard/deploy/bin/app.ts` to your actual VPC ID
2. Create GitHub environments (`Guard Dev`, `Guard Prod`) and add secrets
3. Run `cd guard/deploy && pnpm install && VPC_ID=vpc-xxx npx cdk synth` to verify

**Why NLB (not ALB):**
ALB terminates HTTP/2 and re-opens HTTP/1.1 to backends, breaking gRPC.
NLB does TCP passthrough — the HTTP/2 connection goes end-to-end.

### Dockerfile

Multi-stage build at `guard/deploy/Dockerfile`. Build context is repo root.

```
Builder:  golang:1.25-alpine → go mod download → go build (static, CGO_ENABLED=0)
Runtime:  gcr.io/distroless/static-debian12:nonroot (<20MB, no shell)
Port:     50051
```

```bash
# Build locally:
docker build -f guard/deploy/Dockerfile -t palisade-guard:test .

# Build + push to ECR:
./guard/scripts/create_docker.sh 0.1.0
```

### ECS Deployment Details

- **Rolling deployment:** ECS starts new tasks (maxHealthy=200%), waits for NLB health check,
  then drains old tasks. Zero downtime since min 2 tasks.
- **Circuit breaker:** If new tasks crash-loop, ECS auto-rolls back to the previous version.
- **Health check:** NLB TCP check on port 50051 (gRPC server listening = healthy).
- **Graceful shutdown:** Guard server catches SIGTERM, marks health as NOT_SERVING,
  then `GracefulStop()` drains in-flight RPCs.
- **Logs:** Structured JSON (zap) → CloudWatch. View with:
  ```bash
  aws logs tail /ecs/palisade-guard-dev --follow
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

---

## What NOT to Build (Phase 1 Scope)

Explicitly out of scope — do not implement these yet:

- [ ] PostgreSQL project lookup (stub only — `StaticAuthenticator`)
- [ ] `CheckBatch` RPC (proto exists, server returns Unimplemented)
- [ ] Per-project policies or detector configuration
- [ ] Custom rules engine
- [ ] ML-based detectors
- [ ] TLS termination (NLB handles this in production)
- [ ] Metrics/Prometheus endpoint
- [ ] Rate limiting
- [ ] Gateway service (`gateway/` is a separate service)
