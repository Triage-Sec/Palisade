# Palisade — Guard Service

## Architecture

Single Go service serving HTTP REST on `:8080`. No gRPC server, no Python backend.

```
SDK/Dashboard → HTTP :8080 → Go Guard Service → Engine → Response
                                 ├── Postgres (auth, projects, policies)
                                 ├── ClickHouse (write events, read events/analytics)
                                 └── PromptGuard gRPC client (ML detector)
```

## Package Layout

```
guard/
├── cmd/guard-server/main.go          # HTTP server bootstrap, wiring
├── internal/
│   ├── api/                          # HTTP REST layer
│   │   ├── router.go                 # Go 1.22+ net/http routing, CORS, health
│   │   ├── check.go                  # POST /v1/palisade
│   │   ├── projects.go               # Project CRUD
│   │   ├── policies.go               # Policy CRUD
│   │   ├── events.go                 # Events + analytics
│   │   ├── middleware.go             # Auth (tsk_ bearer + bcrypt + cache), logging, JSON helpers
│   │   └── types.go                  # JSON request/response structs
│   ├── store/                        # Postgres data access (pgx/v5)
│   │   ├── store.go                  # Store struct, connection pool
│   │   ├── projects.go               # Project CRUD + API key generation
│   │   └── policies.go               # Policy CRUD
│   ├── chread/                       # ClickHouse read path
│   │   └── events.go                 # Event listing, analytics
│   ├── engine/                       # Detection engine
│   │   ├── engine.go                 # SentryEngine: parallel fan-out
│   │   ├── detector.go               # Detector interface
│   │   ├── types.go                  # Verdict, ActionType, ThreatCategory, DetectorResult
│   │   ├── aggregator.go             # Results → verdict (per-detector thresholds)
│   │   ├── defaults.go               # Default timeout
│   │   ├── policy.go                 # PolicyConfig, DetectorPolicy
│   │   └── detectors/
│   │       ├── ml_prompt_injection.go  # ML: gRPC client → PromptGuard service
│   │       ├── pii.go                  # Regex: SSN, CC, email, phone, IBAN
│   │       ├── content_mod.go          # Regex: violence, self-harm, illegal
│   │       └── tool_abuse.go           # Regex: blocked fns, SQL/command injection
│   └── storage/                      # ClickHouse write path
│       ├── clickhouse.go             # Buffered async writer
│       └── events.go                 # SecurityEvent struct + EventWriter interface
├── gen/prompt_guard/v1/              # Generated proto code (PromptGuard gRPC client only)
├── deploy/                           # CDK (ECS Fargate + NLB)
├── scripts/
│   ├── create_docker.sh              # Build + push to ECR
│   └── test_requests.sh              # Test PromptGuard ML service
├── migrations/                       # ClickHouse migrations
├── go.mod
└── Makefile
```

## Key Patterns

- **Auth**: `tsk_` API keys, bcrypt-verified, stale-while-revalidate in-memory cache (30s TTL)
- **Engine**: direct in-process call from HTTP handler (no network hop)
- **Detectors**: run in parallel goroutines, share single `context.WithTimeout`
- **Types**: plain Go iota enums (`Verdict`, `ActionType`, `ThreatCategory`) — no protobuf
- **Routing**: Go 1.22+ `net/http` patterns (no third-party router)
- **ClickHouse**: write path in `internal/storage/`, read path in `internal/chread/`
- **Fail-open/fail-closed**: NOT implemented server-side. SDKs decide how to handle errors.

## Environment Variables

| Var | Default | Required | Description |
|-----|---------|----------|-------------|
| `POSTGRES_DSN` | — | Yes | PostgreSQL connection string |
| `GUARD_HTTP_PORT` | `8080` | No | HTTP listen port |
| `GUARD_LOG_LEVEL` | `info` | No | debug, info, warn, error |
| `GUARD_DETECTOR_TIMEOUT_MS` | `100` | No | Max time for detector fan-out |
| `GUARD_BLOCK_THRESHOLD` | `0.8` | No | Default confidence threshold for BLOCK |
| `GUARD_FLAG_THRESHOLD` | `0.0` | No | Default confidence threshold for FLAG |
| `GUARD_AUTH_CACHE_TTL_S` | `30` | No | Auth cache TTL in seconds |
| `CLICKHOUSE_DSN` | — | No | ClickHouse connection (empty = log writer fallback) |
| `PROMPT_GUARD_ENDPOINT` | — | No | PromptGuard gRPC endpoint (empty = ML detector disabled) |

## API Routes

```
# Payload screening (auth: Bearer tsk_)
POST   /v1/palisade

# Project CRUD (no auth — dashboard auth later)
POST   /api/palisade/projects
GET    /api/palisade/projects
GET    /api/palisade/projects/{project_id}
PATCH  /api/palisade/projects/{project_id}
DELETE /api/palisade/projects/{project_id}
POST   /api/palisade/projects/{project_id}/rotate-key

# Policy CRUD (no auth)
GET    /api/palisade/projects/{project_id}/policy
PUT    /api/palisade/projects/{project_id}/policy
PATCH  /api/palisade/projects/{project_id}/policy

# Events & Analytics (no auth)
GET    /api/palisade/events
GET    /api/palisade/events/{request_id}
GET    /api/palisade/analytics

# Health
GET    /healthz
```

## Development

```bash
# Run locally
cd guard && make run          # reads .env from repo root

# Test
cd guard && go test ./... -v -race -count=1

# Build
cd guard && go build -o bin/guard-server ./cmd/guard-server/

# Deploy (tag-based)
git tag guard-dev@0.2.0 && git push origin guard-dev@0.2.0
```

## Deployment

- **Docker**: `golang:1.25-alpine` → `distroless` (<20MB)
- **ECS Fargate**: 2 tasks min, 0.5 vCPU / 1GB, auto-scale to 10
- **NLB**: TCP :8080, health check on `/healthz`
- **CI**: `guard-ci.yml` (lint → test → Docker smoke test)
- **CD**: `guard-deploy.yml` (tag `guard-dev@*` or `guard-prod@*`)
