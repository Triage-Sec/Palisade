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
│   │   └── auth.go                     # API key validation (StaticAuthenticator — hardcoded tsk_ prefix)
│   ├── storage/
│   │   ├── clickhouse.go              # Buffered async ClickHouse writer (fire-and-forget)
│   │   └── events.go                  # SecurityEvent struct + EventWriter interface
│   └── circuit/
│       └── breaker.go                  # Per-detector circuit breakers
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
2. [Auth] Validate API key (tsk_ prefix check — StaticAuthenticator)
3. [Fan-Out] Launch ALL detectors as goroutines with 25ms deadline
4. [Collect] Wait for all detectors or context deadline (missed = skipped)
5. [Aggregate] ANY confidence >= 0.8 → BLOCK, ANY triggered < 0.8 → FLAG, else ALLOW
6. [Log] Fire-and-forget: queue security event to ClickHouse (never blocks)
7. Return CheckResponse with verdict + detector results + latency_ms
```

### Performance Invariants

These are non-negotiable constraints. Every code change must preserve them:

- **Total check latency < 40ms p99**
- **Detector fan-out timeout: 25ms** — detectors that don't finish are skipped
- **Zero heap allocations on the hot path where possible** — reuse buffers, pre-compile regexes
- **No blocking I/O on the hot path** — logging/storage is always async fire-and-forget
- **No mutex contention on check path** — use channels or atomic operations
- **gRPC keepalive: 30s ping** — persistent connections

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
| `GUARD_BLOCK_THRESHOLD` | `0.8` | Confidence threshold for BLOCK verdict |
| `GUARD_FLAG_THRESHOLD` | `0.0` | Confidence threshold for FLAG verdict |
| `CLICKHOUSE_DSN` | `` | ClickHouse connection string (empty = log events to stdout) |

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
git tag guard-dev@0.1.0
git push origin guard-dev@0.1.0

# Deploy to prod (requires manual approval in GitHub):
git tag guard-prod@0.1.0
git push origin guard-prod@0.1.0
```

Or use GitHub Releases UI: create a new release with the tag name.

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

---

## Current State (What's Built)

Phase 1 core is complete and deployed to dev:

- [x] Proto definition + code generation
- [x] Guard gRPC server with health checks
- [x] 5 regex/heuristic detectors (prompt injection, jailbreak, PII, content mod, tool abuse)
- [x] SentryEngine with parallel fan-out + 25ms deadline
- [x] Aggregator (hardcoded thresholds: 0.8 block, any triggered = flag)
- [x] StaticAuthenticator (tsk_ prefix check)
- [x] ClickHouse buffered async writer + LogWriter fallback
- [x] Per-detector circuit breakers
- [x] CI pipeline (lint + test + Docker smoke test)
- [x] Deploy pipeline (tag-based, ECR + CDK + ECS Fargate)
- [x] CDK infrastructure (ECS, NLB, CloudWatch, auto-scaling)

---

## Future Phases

### Phase 2: Auth, Gateway, SDKs

| Item | Description | Where |
|------|-------------|-------|
| PostgreSQL auth | Replace `StaticAuthenticator` with `PostgresAuthenticator` — hash API key, look up project mode/fail_open from `projects` table | `guard/internal/auth/` |
| Projects table | Drizzle schema for projects (api_key_hash, mode, fail_open, checks_per_month) | `parse/packages/db/src/schema/` |
| Python SDK v2 | gRPC client with `check()`, circuit breaker, fail-open, lazy connection | `sdk/python/` |
| TypeScript SDK v2 | Same pattern as Python SDK | `sdk/typescript/` |
| Go SDK v2 | Same pattern | `sdk/go/` |
| Secure AI Gateway | Go HTTP reverse proxy — parse OpenAI/Anthropic requests, screen via Guard gRPC, forward to provider | `gateway/` |
| TLS on NLB | Add TLS termination at the NLB (currently plaintext gRPC) | `guard/deploy/lib/guard-stack.ts` |
| Gateway CDK | ECS Fargate + ALB for the gateway service | `gateway/deploy/` |

### Phase 3: Integrations, Advanced Detectors, Batch

| Item | Description | Where |
|------|-------------|-------|
| LangChain callback | `TriageGuardCallback` — calls `check()` on LLM/tool start/end | `sdk/python/integrations/` |
| CrewAI middleware | Framework integration for CrewAI | `sdk/python/integrations/` |
| Vercel AI hook | `triageGuard()` middleware for Vercel AI SDK | `sdk/typescript/integrations/` |
| ML-based detectors | Replace regex heuristics with trained classifiers | `guard/internal/engine/detectors/` |
| Custom rules engine | Per-project regex/keyword/classifier rules from database | `guard/internal/engine/detectors/custom_rule.go` |
| CheckBatch RPC | Server-streaming batch checks (proto already defined) | `guard/`, `sdk/` |
| Per-project policies | Detector enable/disable + sensitivity per project from Postgres | `guard/internal/engine/` |

### Phase 4: Shadow Mode, Client Export, Dashboard

| Item | Description | Where |
|------|-------------|-------|
| Shadow mode report | Dashboard showing "what would have been blocked" | `parse/apps/web/components/guard/` |
| Security events table | Dashboard table of events from ClickHouse | `parse/apps/web/components/guard/` |
| Threat analytics | Charts: blocks over time, top categories, top users | `parse/apps/web/components/guard/` |
| Policy config UI | Mode toggle, detector config, allowed tools list | `parse/apps/web/components/policy/` |
| Webhook export | Push BLOCK/FLAG events to client's URL | `guard/internal/export/` |
| OTel export | Emit security events as spans to client's OTel collector | `guard/internal/export/` |
| Streaming screening | Real-time token screening in Gateway (buffer-then-screen → mid-stream) | `gateway/internal/proxy/` |
