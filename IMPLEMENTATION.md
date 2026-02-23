# IMPLEMENTATION.md — Triage AI Security Firewall

> **Last updated:** 2026-02-22
>
> Engineering blueprint for Triage's AI security firewall platform.
> Covers the Guard Edge Service (built), SDKs, Gateway, backend changes,
> dashboard, and phased implementation.

---

## Philosophy

**We are the bouncer at the door, not the security camera recording everything inside the club.**

Triage is an AI security firewall. We enforce policies on AI agent actions in real-time (<40ms).
We do NOT ingest, store, or display full application telemetry. We are not Datadog. We are not
LangSmith. We are not Braintrust.

**What we do:**
- Screen LLM inputs/outputs, tool calls, RAG retrievals, and chain-of-thought for threats
- Block or flag dangerous payloads before they execute
- Log enforcement decisions (BLOCK/ALLOW/FLAG) with detector results
- Provide a dashboard for security events, threat analytics, and policy configuration

**What we do NOT do:**
- Auto-instrument client applications
- Ingest full OpenTelemetry trace firehoses
- Store latency metrics, token costs, or general debugging data
- Compete with observability platforms

---

## Architecture Overview

Two integration paths. No third path. No OTel trace ingestion.

```
                    PATH A: GATEWAY                    PATH B: SDK
               (Zero-code integration)            (Explicit check() calls)

  Client App                              Client App
  base_url = gateway.triage.dev           import triage; triage.check(...)
           |                                        |
           v                                        v
  +------------------+                   +------------------+
  | Secure AI Gateway |                  | Triage SDK       |
  | (Go, HTTPS)       |                 | (gRPC client)    |
  | Parse + screen I/O |                | Serialize + send  |
  +--------+----------+                 +--------+---------+
           |                                      |
           +------------------+-------------------+
                              |
                              v
                   +---------------------+
                   | Guard Edge Service   |
                   | (Go, gRPC :50051)    |     +------------+
                   |                      |     | PostgreSQL |
                   | SentryEngine:        |<--->| (Supabase) |
                   | - Prompt injection   |     | projects,  |
                   | - Jailbreak          |     | policies   |
                   | - PII detection      |     +------------+
                   | - Content mod        |
                   | - Tool abuse         |     +------------+
                   | (all run in parallel)|---->| ClickHouse |
                   +----------+-----------+     | security_  |
                              |                 | events     |
                    CheckResponse               +-----+------+
                    (verdict + detectors)              |
                                                      v
                                              +---------------+
                                              | Dashboard     |
                                              | (Next.js)     |
                                              | - Events      |
                                              | - Analytics   |
                                              | - Policies    |
                                              +---------------+
```

---

## Repository Structure

Each service lives in its own repository:

| Repo | Language | Purpose |
|------|----------|---------|
| `Triage-Sec/palisade` | Go | Guard Edge Service — gRPC enforcement engine |
| `Triage-Sec/triage-sdk-python` | Python | Python SDK — `triage.check()` gRPC client |
| `Triage-Sec/triage-sdk-typescript` | TypeScript | TypeScript SDK — `check()` gRPC client |
| `Triage-Sec/triage-gateway` | Go | Secure AI Gateway — HTTP reverse proxy |
| `Triage-Sec/triage` | Python/TypeScript | Backend (FastAPI) + Dashboard (Next.js) |

---

## Part 1: Guard Edge Service (Built & Deployed)

The Guard service is live in dev on ECS Fargate behind an NLB. This section documents
exactly what is built.

### Repository: `Triage-Sec/palisade`

```
guard/
├── cmd/
│   └── guard-server/
│       └── main.go                     # gRPC server bootstrap
├── internal/
│   ├── server/
│   │   └── guard_server.go             # GuardService.Check() implementation
│   ├── engine/
│   │   ├── engine.go                   # SentryEngine: fan-out detector execution
│   │   ├── detector.go                 # Detector interface
│   │   ├── aggregator.go              # Aggregate DetectResults → Verdict
│   │   ├── defaults.go                 # Hardcoded thresholds + detector registry
│   │   └── detectors/
│   │       ├── prompt_injection.go     # 19 regex patterns (0.70-0.95 confidence)
│   │       ├── jailbreak.go            # 17 regex patterns (0.50-0.95 confidence)
│   │       ├── pii.go                  # 8 regex patterns: SSN, CC, email, phone, IBAN
│   │       ├── content_mod.go          # 10 regex patterns + keyword list
│   │       └── tool_abuse.go           # 35 blocked functions + SQL/command injection
│   ├── auth/
│   │   └── auth.go                     # StaticAuthenticator (tsk_ prefix check)
│   ├── storage/
│   │   ├── clickhouse.go              # Buffered async ClickHouse writer
│   │   └── events.go                  # SecurityEvent struct + EventWriter interface
│   └── circuit/                        # Empty — not yet implemented
│       └── (planned: breaker.go)
├── gen/guard/v1/                       # Generated protobuf Go code
├── migrations/                         # ClickHouse DDL
├── deploy/                             # CDK infrastructure (ECS Fargate + NLB)
├── scripts/create_docker.sh            # Build + push Docker image to ECR
├── go.mod
├── go.sum
└── Makefile
```

### Request Flow (Check RPC)

```
1. gRPC unary call → GuardService.Check()
2. [Auth] StaticAuthenticator validates:
   - "Bearer tsk_..." in authorization header
   - x-project-id header present
   - Returns ProjectContext{ProjectID, Mode="enforce", FailOpen=true}
3. [Fan-Out] SentryEngine.Evaluate() launches 5 detectors as goroutines
   - Each gets context.WithTimeout(25ms)
   - Buffered channel collects results
4. [Collect] Main goroutine reads results until all complete or deadline fires
   - Late-finishing detectors: writes buffered, never read, GC'd
5. [Aggregate] engine.Aggregate() applies thresholds:
   - ANY Triggered + Confidence >= 0.8 → BLOCK
   - ANY Triggered + Confidence >= 0.0 but < 0.8 → FLAG
   - Otherwise → ALLOW
6. [Shadow] If project.Mode == "shadow" and verdict != ALLOW:
   - Store REAL verdict in ClickHouse
   - Return ALLOW to client, set is_shadow=true
7. [Log] Fire-and-forget: queue SecurityEvent to ClickHouse writer
   - Buffered channel (10,000 capacity), drop if full
   - Background flush: every 100ms or 1,000 events
8. Return CheckResponse{verdict, detectors[], latency_ms, request_id, is_shadow, reason}
```

### Detector Interface

```go
type Detector interface {
    Name() string
    Category() guardv1.ThreatCategory
    Detect(ctx context.Context, req *DetectRequest) (*DetectResult, error)
}

type DetectRequest struct {
    Payload  string
    Action   guardv1.ActionType
    ToolCall *guardv1.ToolCall
}

type DetectResult struct {
    Triggered  bool
    Confidence float32  // 0.0 – 1.0
    Details    string
}
```

### Implemented Detectors

All use pre-compiled regex patterns (`regexp.MustCompile` at package level). No runtime
compilation. Case-insensitive matching via `(?i)` flag where applicable.

| Detector | Patterns | Confidence Range | What It Catches |
|----------|----------|-----------------|-----------------|
| `prompt_injection` | 19 regex | 0.70–0.95 | "ignore previous instructions", system prompt extraction, delimiter injection, `[SYSTEM]`/`<\|im_start\|>` |
| `jailbreak` | 17 regex | 0.50–0.95 | DAN prompts, developer mode, roleplay jailbreaks, encoding tricks (base64/hex/rot13), token smuggling |
| `pii` | 8 regex | 0.70–0.90 | SSN, credit cards (Visa/MC/Amex/Discover), email, US/intl phone, IBAN |
| `content_mod` | 10 regex + keywords | 0.85–0.99 | Violence, self-harm, CSAM (0.99), illegal activity, drug synthesis |
| `tool_abuse` | 35 blocked fns + 15 regex | 0.90–0.95 | exec/eval/system/rm, SQL injection (DROP/UNION/xp_cmdshell), command injection (`;`, `\|`, backticks) |

### Auth Interface

```go
type Authenticator interface {
    Authenticate(ctx context.Context) (*ProjectContext, error)
}

type ProjectContext struct {
    ProjectID string
    Mode      string  // "enforce" or "shadow"
    FailOpen  bool
}
```

**Current:** `StaticAuthenticator` — checks `tsk_` prefix, hardcodes Mode="enforce", FailOpen=true.
**Future:** `PostgresAuthenticator` — hash API key, look up project config from `projects` table.

### Storage (EventWriter)

```go
type EventWriter interface {
    Write(event *SecurityEvent)  // Non-blocking. Drops if buffer full.
    Close()                      // Drain buffer, flush, close connection.
}
```

**ClickHouseWriter:** Buffered channel (10,000), background flush (100ms / 1,000 events),
batch INSERT, 5s timeout per batch, 2s drain on Close(). TLS enforced.

**LogWriter:** Fallback when `CLICKHOUSE_DSN=""`. Logs events as structured JSON to stdout.

### Environment Variables

| Var | Default | Description |
|-----|---------|-------------|
| `GUARD_PORT` | `50051` | gRPC listen port |
| `GUARD_LOG_LEVEL` | `info` | debug, info, warn, error |
| `GUARD_DETECTOR_TIMEOUT_MS` | `25` | Max time for detector fan-out |
| `GUARD_BLOCK_THRESHOLD` | `0.8` | Confidence threshold for BLOCK |
| `GUARD_FLAG_THRESHOLD` | `0.0` | Confidence threshold for FLAG |
| `CLICKHOUSE_DSN` | `` | ClickHouse connection string (empty = stdout logging) |

### gRPC Server Configuration

```go
grpc.NewServer(
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
    grpc.MaxRecvMsgSize(4 * 1024 * 1024),  // 4MB
    grpc.MaxSendMsgSize(4 * 1024 * 1024),
)
```

Health check: `grpc.health.v1.Health` registered with service name `triage.guard.v1.GuardService`.
Reflection enabled for `grpcurl` debugging.

### Dependencies (go.mod)

```
google.golang.org/grpc                   # gRPC server
google.golang.org/protobuf               # Protobuf runtime
go.uber.org/zap                          # Structured logging
github.com/ClickHouse/clickhouse-go/v2   # ClickHouse client
github.com/google/uuid                   # UUID generation
```

### Deployment

Deployed to ECS Fargate behind NLB. See CLAUDE.md for full CI/CD details.

```
Docker image: golang:1.25-alpine → distroless (<20MB)
ECS: 2 tasks min, 0.5 vCPU / 1GB, auto-scale to 10
NLB: TCP :50051 (gRPC requires NLB, not ALB)
Subnets: Public (assignPublicIp=true for ClickHouse Cloud)
CI: guard-ci.yml (lint → test → Docker smoke test)
Deploy: guard-deploy.yml (tag guard-dev@* or guard-prod@*)
```

---

## Part 2: Protobuf Schema (Built)

File: `proto/guard/v1/guard.proto` — shared across Guard service, SDKs, and Gateway.

```protobuf
syntax = "proto3";
package triage.guard.v1;
option go_package = "github.com/triage-ai/palisade/gen/guard/v1;guardv1";

service GuardService {
    rpc Check(CheckRequest) returns (CheckResponse);
    rpc CheckBatch(CheckBatchRequest) returns (stream CheckResponse);  // Phase 3
}

enum ActionType {
    ACTION_TYPE_UNSPECIFIED = 0;
    ACTION_TYPE_LLM_INPUT = 1;
    ACTION_TYPE_LLM_OUTPUT = 2;
    ACTION_TYPE_TOOL_CALL = 3;
    ACTION_TYPE_TOOL_RESULT = 4;
    ACTION_TYPE_RAG_RETRIEVAL = 5;
    ACTION_TYPE_CHAIN_OF_THOUGHT = 6;
    ACTION_TYPE_DB_QUERY = 7;
    ACTION_TYPE_CUSTOM = 8;
}

enum Verdict {
    VERDICT_UNSPECIFIED = 0;
    VERDICT_ALLOW = 1;
    VERDICT_BLOCK = 2;
    VERDICT_FLAG = 3;
}

enum ThreatCategory {
    THREAT_CATEGORY_UNSPECIFIED = 0;
    THREAT_CATEGORY_PROMPT_INJECTION = 1;
    THREAT_CATEGORY_JAILBREAK = 2;
    THREAT_CATEGORY_PII_LEAKAGE = 3;
    THREAT_CATEGORY_CONTENT_MODERATION = 4;
    THREAT_CATEGORY_TOOL_ABUSE = 5;
    THREAT_CATEGORY_DATA_EXFILTRATION = 6;
    THREAT_CATEGORY_CUSTOM_RULE = 7;
}

message CheckRequest {
    string payload = 1;
    ActionType action = 2;
    Identity identity = 3;
    string client_trace_id = 4;
    ToolCall tool_call = 5;
    map<string, string> metadata = 6;
    string project_id = 7;
}

message CheckResponse {
    Verdict verdict = 1;
    repeated DetectorResult detectors = 2;
    float latency_ms = 3;
    string request_id = 4;
    bool is_shadow = 5;
    string reason = 6;
}

message DetectorResult {
    string detector = 1;
    bool triggered = 2;
    float confidence = 3;
    ThreatCategory category = 4;
    string details = 5;
}

message Identity {
    string user_id = 1;
    string session_id = 2;
    string tenant_id = 3;
}

message ToolCall {
    string function_name = 1;
    string arguments_json = 2;
}

message CheckBatchRequest {
    repeated CheckRequest requests = 1;
}
```

---

## Part 3: ClickHouse Schema (Built)

The `security_events` table is the only runtime data store. One row per `check()` call.
Migration lives at `guard/migrations/000001_create_security_events.up.sql`. Table is live in ClickHouse Cloud.

```sql
CREATE TABLE IF NOT EXISTS security_events (
    request_id          UUID DEFAULT generateUUIDv4(),
    project_id          String,
    timestamp           DateTime64(3, 'UTC'),
    action              Enum8(
        'llm_input' = 1, 'llm_output' = 2, 'tool_call' = 3, 'tool_result' = 4,
        'rag_retrieval' = 5, 'chain_of_thought' = 6, 'db_query' = 7, 'custom' = 8
    ),
    payload_preview     String,
    payload_hash        FixedString(32),
    payload_size        UInt32,
    verdict             Enum8('allow' = 1, 'block' = 2, 'flag' = 3),
    is_shadow           UInt8,
    reason              String,
    detector_names      Array(String),
    detector_triggered  Array(UInt8),
    detector_confidences Array(Float32),
    detector_categories Array(String),
    detector_details    Array(String),
    user_id             String,
    session_id          String,
    tenant_id           String,
    client_trace_id     String,
    tool_name           String,
    tool_arguments      String,
    metadata            Map(String, String),
    latency_ms          Float32,
    source              Enum8('sdk' = 1, 'gateway' = 2),
    sdk_language        String,
    sdk_version         String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (project_id, timestamp, request_id)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Secondary indexes
ALTER TABLE security_events ADD INDEX IF NOT EXISTS idx_verdict verdict TYPE set(3) GRANULARITY 4;
ALTER TABLE security_events ADD INDEX IF NOT EXISTS idx_action action TYPE set(8) GRANULARITY 4;
ALTER TABLE security_events ADD INDEX IF NOT EXISTS idx_user_id user_id TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE security_events ADD INDEX IF NOT EXISTS idx_is_shadow is_shadow TYPE set(2) GRANULARITY 4;
```

**Why ClickHouse:**
- Append-only, high-volume writes (millions/day per customer)
- Aggregation-heavy dashboard queries
- 90%+ columnar compression
- Native TTL (auto-delete after 90 days)
- PostgreSQL (Supabase) would choke on this volume

---

## Part 4: Python SDK

### Repository: `Triage-Sec/triage-sdk-python`

New repo, clean start. No OTel, no Traceloop, no span exporting.
Just a gRPC client with one function: `check()`.

```
triage-sdk-python/
├── src/triage_sdk/
│   ├── __init__.py              # Public API: init, check, check_sync, shutdown
│   ├── config.py                # TriageConfig (args > env vars > defaults)
│   ├── client.py                # gRPC channel: lazy connect, keepalive, reconnect
│   ├── check.py                 # check() → serialize → gRPC unary → Decision
│   ├── types.py                 # Decision, ActionType, Verdict, DetectorResult
│   ├── circuit_breaker.py       # Fail-open after N consecutive failures
│   ├── redactor.py              # Optional pre-send PII stripping (regex)
│   ├── version.py               # "1.0.0"
│   └── _proto/
│       ├── guard_pb2.py         # Generated from proto/guard/v1/guard.proto
│       └── guard_pb2_grpc.py    # Generated gRPC stubs
├── tests/
├── pyproject.toml
└── README.md
```

### Public API

```python
import triage
from triage import ActionType

triage.init(api_key="tsk_...", project_id="proj_...")

# Screen input before it reaches the LLM — returns in <40ms
decision = await triage.check(
    payload=user_prompt,
    action=ActionType.LLM_INPUT,
    user_id="user_123",
    session_id="sess_456",
)

if decision.blocked:
    raise SecurityError(f"Blocked: {decision.triggered_detectors}")

# Screen output before it reaches the end user
decision = await triage.check(
    payload=response.content,
    action=ActionType.LLM_OUTPUT,
    user_id="user_123",
)

# Screen a tool call before execution
decision = await triage.check(
    action=ActionType.TOOL_CALL,
    payload=json.dumps({"query": agent_proposed_sql}),
    user_id="user_123",
)
```

### Function Signatures

```python
def init(
    api_key: str | None = None,          # env: TRIAGE_API_KEY
    project_id: str | None = None,       # env: TRIAGE_PROJECT_ID
    endpoint: str = "guard.triage.dev:443",  # env: TRIAGE_ENDPOINT
    timeout_ms: int = 30,
    fail_open: bool = True,
    enabled: bool = True,                # env: TRIAGE_ENABLED
) -> None

async def check(
    payload: str | dict | list,
    action: ActionType,
    *,
    user_id: str | None = None,
    session_id: str | None = None,
    tenant_id: str | None = None,
    trace_id: str | None = None,
    metadata: dict[str, str] | None = None,
) -> Decision

def check_sync(...) -> Decision  # Blocking wrapper

def shutdown() -> None
```

### Types

```python
class ActionType(str, Enum):
    LLM_INPUT = "llm_input"
    LLM_OUTPUT = "llm_output"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    RAG_RETRIEVAL = "rag_retrieval"
    CHAIN_OF_THOUGHT = "chain_of_thought"
    DB_QUERY = "db_query"
    CUSTOM = "custom"

class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"

@dataclass(frozen=True)
class DetectorResult:
    detector: str
    triggered: bool
    confidence: float
    category: str
    details: str | None

@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    triggered_detectors: list[DetectorResult]
    latency_ms: float
    request_id: str
    is_shadow: bool

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    @property
    def allowed(self) -> bool:
        return self.verdict != Verdict.BLOCK
```

### gRPC Client Lifecycle

```
init() → store config, do NOT open connection (lazy)
        |
first check() → open persistent gRPC channel
                  - TLS by default
                  - Keepalive ping every 30s
                  - Max message: 4MB
                  - Compression: gzip
                  - Metadata: authorization=Bearer <api_key>, x-project-id=<project_id>
        |
subsequent check() → reuse channel, send unary RPC with deadline=timeout_ms
        |
timeout/error → circuit breaker records failure
                  → return fail-open Decision (verdict=ALLOW)
        |
5 consecutive failures → breaker OPEN → skip gRPC, return ALLOW immediately
        |
after 10s → breaker HALF-OPEN → allow 1 probe call
        |
probe succeeds → breaker CLOSED → normal operation
        |
shutdown() → drain in-flight (1s max) → close channel
```

### Dependencies

```
grpcio >= 1.60.0
protobuf >= 4.25.0
```

That's it. No OTel, no Traceloop, no HTTP libraries.

---

## Part 5: TypeScript SDK

### Repository: `Triage-Sec/triage-sdk-typescript`

Same architecture as Python SDK. gRPC client with `check()`.

```
triage-sdk-typescript/
├── src/
│   ├── index.ts                 # Public API: init, check, shutdown
│   ├── config.ts                # TriageConfig
│   ├── client.ts                # gRPC channel management
│   ├── check.ts                 # check() implementation
│   ├── types.ts                 # Decision, ActionType, Verdict, DetectorResult
│   ├── circuit-breaker.ts       # Fail-open circuit breaker
│   └── proto/
│       └── guard/v1/            # Generated from proto/guard/v1/guard.proto
├── tests/
├── package.json
├── tsconfig.json
└── README.md
```

### Public API

```typescript
import { init, check, ActionType } from '@triage-sec/sdk';

init({ apiKey: 'tsk_...', projectId: 'proj_...' });

const decision = await check(userPrompt, ActionType.LLM_INPUT, {
    userId: 'user_123',
    sessionId: 'sess_456',
});

if (decision.blocked) throw new Error(`Blocked: ${decision.reason}`);
```

### Dependencies

```
@grpc/grpc-js
google-protobuf
```

---

## Part 6: Secure AI Gateway

### Repository: `Triage-Sec/triage-gateway`

Go HTTP reverse proxy. Client points `base_url` at the Gateway instead of directly
at OpenAI/Anthropic. Gateway parses the request, screens via Guard gRPC `check()`,
then forwards to the real provider.

```
triage-gateway/
├── cmd/
│   └── gateway-server/
│       └── main.go                     # HTTP server entrypoint
├── internal/
│   ├── proxy/
│   │   ├── proxy.go                    # Core reverse proxy logic
│   │   ├── router.go                   # Route to provider parser by URL path
│   │   └── providers/
│   │       ├── openai.go               # Parse OpenAI chat completions format
│   │       ├── anthropic.go            # Parse Anthropic messages format
│   │       └── generic.go              # Passthrough for unknown providers
│   ├── screening/
│   │   └── screen.go                   # Extract payload → Guard gRPC check() → decide
│   ├── auth/
│   │   └── auth.go                     # Validate X-Triage-Key header
│   └── config/
│       └── config.go                   # Gateway configuration
├── deploy/
│   ├── Dockerfile
│   └── lib/gateway-stack.ts            # CDK: ECS Fargate + ALB
├── go.mod
└── README.md
```

### Request Flow

```
Client → gateway.triage.dev/v1/chat/completions
    |
    v
[Auth] Validate X-Triage-Key header against projects table
    |
    v
[Route] URL path determines provider:
    /v1/chat/completions     → OpenAI parser
    /v1/messages             → Anthropic parser
    |
    v
[Screen Input] Guard.Check(payload=user_messages, action=LLM_INPUT)
    |
    +-- BLOCKED → return 403 {"error": {"type": "blocked", "request_id": "..."}}
    +-- ALLOWED → continue
    |
    v
[Forward] Swap Triage key for provider key, proxy request to provider
    |
    v
[Receive Response] from api.openai.com / api.anthropic.com
    |
    v
[Screen Output] Guard.Check(payload=completion_text, action=LLM_OUTPUT)
    |
    +-- BLOCKED → return 403
    +-- ALLOWED → return original provider response to client
```

### Deployment

Separate ECS Fargate service. Uses ALB (HTTP, not gRPC).

```
ECS Cluster (shared VPC)
├── triage-backend    (existing, Python/FastAPI, port 8000, ALB)
├── palisade-guard    (Go/gRPC, port 50051, NLB)
└── triage-gateway    (Go/HTTP, port 443, ALB)
```

---

## Part 7: Backend Changes

### Repository: `Triage-Sec/triage` (existing backend)

The existing FastAPI backend at `https://github.com/Triage-Sec/triage.git` needs
new tables and API endpoints for project management, policy configuration, and
security event querying.

### New PostgreSQL Tables (Drizzle)

#### `projects` table

```typescript
// parse/packages/db/src/schema/projects.ts
export const projects = pgTable('projects', {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    organizationId: uuid('organization_id').references(() => organizations.id),

    // API key (stored hashed, prefix for display)
    apiKeyHash: text('api_key_hash').notNull(),
    apiKeyPrefix: text('api_key_prefix').notNull(),  // "tsk_abc..." first 8 chars

    // Enforcement settings
    mode: text('mode').default('shadow').notNull(),   // "enforce" | "shadow"
    failOpen: boolean('fail_open').default(true).notNull(),

    // Limits
    checksPerMonth: integer('checks_per_month').default(100000),

    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});
```

#### `policies` table

```typescript
// parse/packages/db/src/schema/policies.ts
export const policies = pgTable('policies', {
    id: uuid('id').primaryKey().defaultRandom(),
    projectId: uuid('project_id').references(() => projects.id).notNull(),

    // Which detectors are enabled
    promptInjectionEnabled: boolean('prompt_injection_enabled').default(true).notNull(),
    jailbreakEnabled: boolean('jailbreak_enabled').default(true).notNull(),
    piiEnabled: boolean('pii_enabled').default(true).notNull(),
    contentModEnabled: boolean('content_mod_enabled').default(true).notNull(),
    toolAbuseEnabled: boolean('tool_abuse_enabled').default(true).notNull(),

    // Sensitivity overrides (null = use server defaults)
    blockThreshold: real('block_threshold'),   // e.g., 0.8
    flagThreshold: real('flag_threshold'),      // e.g., 0.5

    // Tool abuse config
    allowedTools: jsonb('allowed_tools'),       // ["search", "calculate", ...]
    blockedTools: jsonb('blocked_tools'),       // ["exec", "eval", ...]

    // Custom keyword blocklist
    customBlocklist: jsonb('custom_blocklist'), // ["keyword1", "keyword2", ...]

    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});
```

#### `provider_keys` table

```typescript
// parse/packages/db/src/schema/provider_keys.ts
export const providerKeys = pgTable('provider_keys', {
    id: uuid('id').primaryKey().defaultRandom(),
    projectId: uuid('project_id').references(() => projects.id).notNull(),
    provider: text('provider').notNull(),        // "openai" | "anthropic"
    encryptedKey: text('encrypted_key').notNull(), // AES-256 encrypted
    createdAt: timestamp('created_at').defaultNow().notNull(),
});
```

### New API Routes (FastAPI)

```python
# Project management
POST   /api/guard/projects              # Create project, generate tsk_ API key
GET    /api/guard/projects              # List projects
GET    /api/guard/projects/:id          # Get project details
PATCH  /api/guard/projects/:id          # Update mode, fail_open, limits
DELETE /api/guard/projects/:id          # Delete project

# Policy management
GET    /api/guard/projects/:id/policy   # Get project policy
PUT    /api/guard/projects/:id/policy   # Update policy (detectors, thresholds, tools)

# Security events (queries ClickHouse)
GET    /api/guard/events                # List events (paginated, filterable)
GET    /api/guard/events/:request_id    # Single event detail
GET    /api/guard/analytics             # Aggregated stats (blocks/day, top categories, etc.)

# Provider keys (for Gateway)
POST   /api/guard/projects/:id/keys     # Store encrypted provider key
DELETE /api/guard/projects/:id/keys/:kid # Remove key
```

### API Key Generation

When a project is created, the backend:
1. Generates a random API key: `tsk_` + 32 random hex chars
2. Returns the full key to the user **once** (never stored in plaintext)
3. Stores `bcrypt(key)` in `api_key_hash` and first 8 chars in `api_key_prefix`
4. Guard service (Phase 2) will hash incoming keys and look up in this table

---

## Part 8: Dashboard Changes

### Repository: `Triage-Sec/triage` (existing Next.js app at `parse/apps/web/`)

New components for runtime security enforcement views.

### New Components

```
parse/apps/web/src/components/
  guard/
    security-events-table.tsx     # Table of security_events from ClickHouse
    event-detail-drawer.tsx       # Slide-out: full event details + detector breakdown
    threat-analytics.tsx          # Charts: blocks over time, top categories, top users
    shadow-mode-report.tsx        # "What would have been blocked" summary
    latency-chart.tsx             # P50/P95/P99 enforcement latency
  policy/
    policy-editor.tsx             # Mode toggle (enforce/shadow), detector config
    detector-config.tsx           # Per-detector enable/disable + sensitivity slider
    allowed-tools-list.tsx        # Tool whitelist manager
  project/
    project-settings.tsx          # Project creation, API key management
    integration-guide.tsx         # Setup instructions for SDK + Gateway
```

### Key ClickHouse Queries

```sql
-- Blocked threats over time (7-day sparkline)
SELECT toStartOfHour(timestamp) as hour, count()
FROM security_events
WHERE project_id = ? AND verdict = 'block' AND timestamp > now() - INTERVAL 7 DAY
GROUP BY hour ORDER BY hour;

-- Top threat categories
SELECT arrayJoin(detector_categories) as cat, count()
FROM security_events
WHERE project_id = ? AND verdict IN ('block', 'flag')
GROUP BY cat ORDER BY 2 DESC LIMIT 10;

-- Shadow mode report
SELECT count() as total,
       countIf(verdict = 'block') as would_block,
       countIf(verdict = 'flag') as would_flag
FROM security_events
WHERE project_id = ? AND is_shadow = 1 AND timestamp > now() - INTERVAL 7 DAY;

-- Enforcement latency percentiles
SELECT quantiles(0.5, 0.95, 0.99)(latency_ms)
FROM security_events
WHERE project_id = ? AND timestamp > now() - INTERVAL 1 DAY;
```

---

## Part 9: Shadow Mode

Shadow mode does NOT require a separate pipeline. Same flow, different enforcement toggle.

1. Client integrates via Gateway or SDK `check()` — identical setup
2. Guard service evaluates all detectors normally
3. If `mode="shadow"`: verdict overridden to ALLOW, `is_shadow=true`
4. ClickHouse stores the **real** verdict (for dashboard analytics)
5. Client's application is never blocked — zero production impact
6. Dashboard shows "what would have been blocked" report

**Going live:** Flip `mode` from `"shadow"` to `"enforce"` in project settings.
No code changes, no deployment, no migration.

---

## Implementation Phases

### Phase 1: Guard Core (DONE)

Everything in this phase is built and deployed to dev.

- [x] Proto definition + code generation
- [x] Guard gRPC server with health checks + graceful shutdown
- [x] 5 regex/heuristic detectors (prompt injection, jailbreak, PII, content mod, tool abuse)
- [x] SentryEngine with parallel fan-out + 25ms deadline
- [x] Aggregator (hardcoded thresholds: 0.8 block, 0.0 flag)
- [x] StaticAuthenticator (tsk_ prefix check)
- [x] ClickHouse buffered async writer + LogWriter fallback
- [x] ClickHouse migration (security_events table)
- [x] CI pipeline (guard-ci.yml: lint + test + Docker smoke test)
- [x] Deploy pipeline (guard-deploy.yml: tag-based, ECR + CDK + ECS Fargate)
- [x] CDK infrastructure (ECS, NLB, CloudWatch, auto-scaling)

### Phase 2: SDKs + Backend + Auth

| Item | Repo | Description |
|------|------|-------------|
| Python SDK | `triage-sdk-python` | gRPC client with `check()`, circuit breaker, fail-open |
| TypeScript SDK | `triage-sdk-typescript` | Same pattern as Python |
| Projects table | `triage` | Drizzle schema, API routes for CRUD |
| Policies table | `triage` | Drizzle schema, API routes for policy config |
| Provider keys table | `triage` | Encrypted storage of OpenAI/Anthropic API keys |
| PostgresAuthenticator | `palisade` | Replace StaticAuthenticator — hash key, look up project |
| Per-project config | `palisade` | Guard reads mode/fail_open/policies from Postgres |
| Circuit breaker | `palisade` | Per-detector circuit breakers in `guard/internal/circuit/` |
| TLS on NLB | `palisade` | Add TLS termination (currently plaintext gRPC) |

### Phase 3: Gateway + Dashboard

| Item | Repo | Description |
|------|------|-------------|
| Secure AI Gateway | `triage-gateway` | Go HTTP reverse proxy — OpenAI/Anthropic providers |
| Gateway CDK | `triage-gateway` | ECS Fargate + ALB deployment |
| Security events page | `triage` | Dashboard table + event detail drawer |
| Threat analytics | `triage` | Charts: blocks over time, top categories, top users |
| Shadow mode report | `triage` | "What would have been blocked" dashboard |
| Policy config UI | `triage` | Mode toggle, detector enable/disable, sensitivity |
| Project settings UI | `triage` | Project creation, API key management, integration guide |
| ClickHouse query API | `triage` | Backend routes to query security_events for dashboard |

### Phase 4: Integrations + Advanced Detectors

| Item | Repo | Description |
|------|------|-------------|
| LangChain callback | `triage-sdk-python` | `TriageGuardCallback` — check on LLM/tool start/end |
| CrewAI middleware | `triage-sdk-python` | Framework integration |
| Vercel AI hook | `triage-sdk-typescript` | `triageGuard()` middleware |
| ML-based detectors | `palisade` | Replace regex heuristics with trained classifiers |
| Custom rules engine | `palisade` | Per-project regex/keyword/classifier rules from DB |
| CheckBatch RPC | `palisade` + SDKs | Server-streaming batch checks |
| Per-project policies | `palisade` | Detector enable/disable + sensitivity from Postgres |

### Phase 5: Export + Streaming

| Item | Repo | Description |
|------|------|-------------|
| Webhook export | `palisade` | Push BLOCK/FLAG events to client's URL |
| OTel export | `palisade` | Emit events as spans to client's OTel collector |
| Streaming screening | `triage-gateway` | Buffer-then-screen → mid-stream token screening |
| Latency analytics | `triage` | P50/P95/P99 enforcement latency charts |

---

## Verification Checklist

### Phase 2
- [ ] `pip install triage-sdk` works
- [ ] `triage.check()` → Guard → verdict in <40ms
- [ ] Circuit breaker: kill Guard, SDK returns fail-open ALLOW
- [ ] Backend: create project, get API key
- [ ] Guard: PostgresAuthenticator validates real API key
- [ ] Dashboard: project settings page

### Phase 3
- [ ] Gateway screens OpenAI request: `curl -H "X-Triage-Key: tsk_..." gateway.triage.dev/v1/chat/completions`
- [ ] Security event in ClickHouse within 200ms
- [ ] Dashboard displays event at `/review/runtime`
- [ ] Policy change in dashboard → Guard picks up within 30s
