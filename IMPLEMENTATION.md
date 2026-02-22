# IMPLEMENTATION.md — Triage AI Security Firewall

> **Last updated:** 2026-02-19
>
> This document is the engineering blueprint for Triage's product pivot from an AI observability
> platform to an AI security firewall. It covers architecture, schemas, SDK design, backend
> services, database design, and phased implementation.

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
- Compete with observability platforms for the client's telemetry budget

### Competitive Positioning

| | Lakera Guard | Triage | Braintrust | Datadog LLM Obs |
|---|---|---|---|---|
| **Core** | AI firewall | AI firewall + code analysis | AI eval + observability | Full APM |
| **Integration** | API call / gateway | API call / gateway / SDK | SDK wrapping + OTel | Agent + OTel |
| **Enforcement** | Inline blocking | Inline blocking | None (post-hoc) | None (post-hoc) |
| **Latency** | <40ms | <40ms target | N/A (async) | N/A (async) |
| **Trace ingestion** | No | No | Yes (full traces) | Yes (full traces) |
| **Unique** | Threat intelligence | Code analysis + runtime | Evals + scoring | Full stack APM |

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
                   | (Go, gRPC :50051)    |     +----------+
                   |                      |<--->| Postgres |
                   | Sentry ML Engine:    |     | policies |
                   | - Prompt injection   |     +----------+
                   | - Jailbreak          |
                   | - PII detection      |     +------------+
                   | - Content mod        |---->| ClickHouse |
                   | - Tool abuse         |     | security_  |
                   | - Custom rules       |     | events     |
                   | (all run in parallel)|     +-----+------+
                   +----------+-----------+           |
                              |                       |
                    CheckResponse                     |
                    (verdict + detectors)              v
                                              +---------------+
                                              | Dashboard     |
                                              | (Next.js)     |
                                              | - Events      |
                                              | - Analytics   |
                                              | - Policies    |
                                              +---------------+
```

### What Each Path Covers

| Threat | Gateway (Path A) | SDK check() (Path B) |
|--------|:-:|:-:|
| Prompt injection | Inline block | Inline block |
| Jailbreaks | Inline block | Inline block |
| PII in prompts | Inline block | Inline block |
| PII in responses | Inline block | Inline block |
| Malicious tool calls | — | Inline block |
| RAG poisoning | — | Inline block |
| SQL/command injection via tools | — | Inline block |
| Chain-of-thought manipulation | — | Inline block |
| Reward hacking / behavioral drift | — | Async detection via historical security_events |

---

## Part 1: SDK Architecture

### Current State (v1 — to be deprecated)

The existing SDKs at `sdk/python/`, `sdk/typescript/`, `sdk/go/` are full OTel tracing pipelines:
- Depend on OpenLLMetry/Traceloop for auto-instrumentation of 37+ LLM providers
- Export ALL spans via OTLP/HTTP `BatchSpanProcessor` to `POST /v1/traces`
- 6 context helpers: `set_user`, `set_tenant`, `set_session`, `set_input`, `set_template`, `set_chunk_acls`
- Config: `api_key`, `endpoint`, `app_name`, `environment`, `enabled`, `trace_content`

**All of this is replaced.** The new SDK has no Traceloop, no OTLP, no span exporting.

### New Public API (v2)

The SDK becomes radically simpler. Just a gRPC client with one function: `check()`.

**Python:**
```python
import triage
from triage import ActionType

triage.init(api_key="tsk_...", project_id="proj_...")

# Screen the input BEFORE it reaches the LLM — returns in <40ms
decision = await triage.check(
    payload=user_prompt,
    action=ActionType.LLM_INPUT,
    user_id="user_123",
    session_id="sess_456",
)

if decision.blocked:
    raise SecurityError(f"Blocked: {decision.triggered_detectors}")

# Normal LLM call — their observability captures this, not us
response = await openai.chat.completions.create(...)

# Screen the output BEFORE it reaches the end user
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

# Screen RAG retrieval before injection into prompt
decision = await triage.check(
    action=ActionType.RAG_RETRIEVAL,
    payload="\n".join(retrieved_documents),
    user_id="user_123",
)
```

**TypeScript:**
```typescript
import { init, check, ActionType } from '@triage-sec/sdk';

init({ apiKey: 'tsk_...', projectId: 'proj_...' });

const decision = await check(userPrompt, ActionType.LLM_INPUT, {
    userId: 'user_123',
    sessionId: 'sess_456',
});

if (decision.blocked) throw new Error(`Blocked: ${decision.reason}`);
```

**Go:**
```go
import triage "github.com/Triage-Sec/triage-sdk-go"

shutdown, _ := triage.Init(triage.WithAPIKey("tsk_..."), triage.WithProjectID("proj_..."))
defer shutdown()

decision, _ := triage.Check(ctx, userPrompt, triage.LLMInput,
    triage.WithUserID("user_123"),
    triage.WithSessionID("sess_456"),
)

if decision.Blocked() {
    return fmt.Errorf("blocked: %s", decision.Reason)
}
```

### Function Signatures

```python
# init() — configure the SDK, does NOT open a connection
def init(
    api_key: str | None = None,          # env: TRIAGE_API_KEY (required)
    project_id: str | None = None,       # env: TRIAGE_PROJECT_ID (required)
    endpoint: str = "guard.triage.dev:443",  # env: TRIAGE_ENDPOINT
    mode: Literal["enforce", "shadow"] = "enforce",  # env: TRIAGE_MODE
    timeout_ms: int = 30,                # Max time to wait for verdict
    fail_open: bool = True,              # Return ALLOW on timeout/error
    redact_before_send: bool = False,    # Strip PII before gRPC transmission
    enabled: bool = True,                # env: TRIAGE_ENABLED
) -> None

# check() — the core product: synchronous enforcement checkpoint
async def check(
    payload: str | dict | list,          # Content to screen
    action: ActionType,                  # What kind of content
    *,
    user_id: str | None = None,          # End-user making the action
    session_id: str | None = None,       # Conversation session
    tenant_id: str | None = None,        # Client's tenant (multi-tenant apps)
    trace_id: str | None = None,         # Client's own trace ID for correlation
    metadata: dict[str, str] | None = None,  # Arbitrary key-value pairs
) -> Decision

# check_sync() — blocking wrapper for non-async codebases
def check_sync(
    payload: str | dict | list,
    action: ActionType,
    **kwargs,
) -> Decision

# shutdown() — drain in-flight checks, close gRPC channel
def shutdown() -> None
```

### Types

```python
class ActionType(str, Enum):
    LLM_INPUT = "llm_input"              # User prompt → LLM
    LLM_OUTPUT = "llm_output"            # LLM response → user
    TOOL_CALL = "tool_call"              # Agent wants to execute a tool
    TOOL_RESULT = "tool_result"          # Tool returned data to agent
    RAG_RETRIEVAL = "rag_retrieval"      # Retrieved docs before injection
    CHAIN_OF_THOUGHT = "chain_of_thought"  # Intermediate reasoning step
    DB_QUERY = "db_query"                # Database query string
    CUSTOM = "custom"                    # User-defined action

class Verdict(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    FLAG = "flag"                        # Allow but mark for human review

@dataclass(frozen=True)
class DetectorResult:
    detector: str                        # e.g. "prompt_injection_v2"
    triggered: bool
    confidence: float                    # 0.0 - 1.0
    category: str                        # e.g. "prompt_injection"
    details: str | None                  # Human-readable explanation

@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    triggered_detectors: list[DetectorResult]
    latency_ms: float                    # Server-side processing time
    request_id: str                      # Server-assigned ID (maps to security_events row)
    is_shadow: bool                      # True if shadow mode overrode verdict to ALLOW

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    @property
    def allowed(self) -> bool:
        return self.verdict != Verdict.BLOCK
```

### SDK File Structure

Python (TypeScript and Go follow the same pattern):

```
sdk/python/src/triage_sdk/
  __init__.py              # Public API: init, check, check_sync, shutdown, types
  config.py                # TriageConfig resolution (args > env vars > defaults)
  client.py                # gRPC channel: lazy connect, keepalive, reconnect
  check.py                 # check() impl: serialize → gRPC unary call → deserialize Decision
  types.py                 # Decision, ActionType, Verdict, DetectorResult, TriageBlockedError
  circuit_breaker.py       # Fail-open after N consecutive failures, recovery probe
  redactor.py              # Optional pre-send PII stripping (regex-based)
  version.py               # "2.0.0"
  integrations/
    __init__.py
    langchain.py           # TriageGuardCallback (calls check() on LLM/tool start/end)
    crewai.py              # CrewAI middleware
  _proto/
    guard_pb2.py           # Generated from proto/guard/v1/guard.proto
    guard_pb2_grpc.py      # Generated gRPC stubs
```

**Dependency changes:**
- **REMOVE:** `traceloop-sdk`, `opentelemetry-*`, `opentelemetry-exporter-otlp-proto-http`, all OTel transitive deps
- **ADD:** `grpcio >= 1.60.0`, `protobuf >= 4.25.0`

### gRPC Client Lifecycle

```
init() → store config, do NOT open connection yet (lazy)
                |
first check() → open persistent gRPC channel
                  - TLS enabled by default
                  - Keepalive ping every 30s
                  - Max message size: 4MB
                  - Compression: gzip
                  - Metadata: authorization=Bearer <api_key>, x-project-id=<project_id>
                |
subsequent check() → reuse channel, send unary RPC with deadline=timeout_ms
                |
timeout/error → circuit breaker records failure
                  → return fail-open Decision (verdict=ALLOW, latency_ms=timeout_ms)
                |
5 consecutive failures → breaker OPEN → skip gRPC, return fail-open immediately
                |
after 10s → breaker HALF-OPEN → allow 1 probe call through
                |
probe succeeds → breaker CLOSED → resume normal operation
                |
shutdown() → drain in-flight checks (1s max) → close channel
```

### Framework Integrations

**LangChain** (`sdk/python/src/triage_sdk/integrations/langchain.py`):
```python
from langchain.callbacks.base import BaseCallbackHandler

class TriageGuardCallback(BaseCallbackHandler):
    """Calls triage.check() on LLM inputs, outputs, and tool calls."""

    def __init__(self, *, user_id: str | None = None, session_id: str | None = None):
        self.user_id = user_id
        self.session_id = session_id

    def on_llm_start(self, serialized, prompts, **kwargs):
        for prompt in prompts:
            decision = triage.check_sync(prompt, ActionType.LLM_INPUT,
                                          user_id=self.user_id, session_id=self.session_id)
            if decision.blocked:
                raise TriageBlockedError(decision)

    def on_llm_end(self, response, **kwargs):
        for gen in response.generations:
            for g in gen:
                decision = triage.check_sync(g.text, ActionType.LLM_OUTPUT,
                                              user_id=self.user_id, session_id=self.session_id)
                if decision.blocked:
                    raise TriageBlockedError(decision)

    def on_tool_start(self, serialized, input_str, **kwargs):
        decision = triage.check_sync(input_str, ActionType.TOOL_CALL,
                                      user_id=self.user_id, session_id=self.session_id)
        if decision.blocked:
            raise TriageBlockedError(decision)
```

**Vercel AI SDK** (`sdk/typescript/src/integrations/vercel-ai.ts`):
```typescript
import type { Middleware } from 'ai';

export function triageGuard(opts?: { userId?: string; sessionId?: string }): Middleware {
    return {
        async wrapGenerate({ doGenerate, params }) {
            const inputDecision = await check(
                JSON.stringify(params.prompt), ActionType.LLM_INPUT,
                { userId: opts?.userId, sessionId: opts?.sessionId }
            );
            if (inputDecision.blocked) throw new TriageBlockedError(inputDecision);

            const result = await doGenerate();

            const outputDecision = await check(
                result.text ?? '', ActionType.LLM_OUTPUT,
                { userId: opts?.userId, sessionId: opts?.sessionId }
            );
            if (outputDecision.blocked) throw new TriageBlockedError(outputDecision);

            return result;
        }
    };
}
```

---

## Part 2: Protobuf Schema

File: `proto/guard/v1/guard.proto` (shared across all SDKs and the Guard edge service)

```protobuf
syntax = "proto3";

package triage.guard.v1;

option go_package = "github.com/Triage-Sec/triage/gen/guard/v1;guardv1";

// ==========================================================================
// GuardService — the enforcement hot path
// ==========================================================================

service GuardService {
    // Unary RPC: client sends CheckRequest, server returns CheckResponse.
    // Latency target: <40ms p99.
    rpc Check(CheckRequest) returns (CheckResponse);

    // Server-streaming RPC for batch checks (Phase 3).
    // Client sends N requests, server streams back N responses.
    rpc CheckBatch(CheckBatchRequest) returns (stream CheckResponse);
}

// ==========================================================================
// Enums
// ==========================================================================

// What kind of AI operation is being checked.
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

// The enforcement decision.
enum Verdict {
    VERDICT_UNSPECIFIED = 0;
    VERDICT_ALLOW = 1;
    VERDICT_BLOCK = 2;
    VERDICT_FLAG = 3;       // Allow but mark for human review
}

// Category of detected threat.
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

// ==========================================================================
// Request / Response Messages
// ==========================================================================

message CheckRequest {
    // The content to screen. JSON-serialized if dict/list.
    string payload = 1;

    // What type of AI operation this payload belongs to.
    ActionType action = 2;

    // Identity context (who is making this action).
    Identity identity = 3;

    // Client's own trace/span ID for correlation with their observability.
    string client_trace_id = 4;

    // Structured tool call details (for TOOL_CALL action).
    ToolCall tool_call = 5;

    // Arbitrary key-value metadata for custom rules.
    map<string, string> metadata = 6;

    // Project ID (also in gRPC metadata, duplicated here for logging).
    string project_id = 7;
}

message CheckResponse {
    // The enforcement verdict.
    Verdict verdict = 1;

    // Which detectors fired and their results.
    repeated DetectorResult detectors = 2;

    // Server-side processing latency in milliseconds.
    float latency_ms = 3;

    // Unique ID for this check event (maps to security_events row).
    string request_id = 4;

    // Whether this response was generated in shadow mode.
    bool is_shadow = 5;

    // Human-readable explanation of why the verdict was reached.
    string reason = 6;
}

message DetectorResult {
    // Name of the detector (e.g., "prompt_injection_v2", "pii_ner").
    string detector = 1;

    // Whether this detector considers the payload a threat.
    bool triggered = 2;

    // Confidence score (0.0 to 1.0).
    float confidence = 3;

    // Threat category this detector covers.
    ThreatCategory category = 4;

    // Human-readable detail.
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

**Why unary RPC, not bidirectional streaming:** `check()` is a 1:1 request/response pattern. The
persistent gRPC channel already eliminates connection overhead. Bidirectional streaming would add
stream lifecycle management complexity for zero latency benefit.

---

## Part 3: Guard Edge Service (Go)

New top-level directory: `guard/`

```
guard/
  cmd/
    guard-server/
      main.go                       # gRPC server entrypoint
  internal/
    server/
      guard_server.go               # GuardService implementation
      check_handler.go              # Check RPC handler
    engine/
      sentry.go                     # Sentry ML engine: fan-out detector execution
      detector.go                   # Detector interface
      aggregator.go                 # Aggregate detector results → verdict
      defaults.go                   # Hardcoded detector config, thresholds, block/flag rules
      detectors/
        prompt_injection.go         # Regex + heuristic patterns (hardcoded rules)
        jailbreak.go                # Pattern matching (hardcoded rules)
        pii.go                      # Regex (SSN, CC, email, phone, IBAN)
        content_mod.go              # Keyword + pattern matching
        tool_abuse.go               # Hardcoded allowed-list + argument validation
    auth/
      project.go                    # Validate API key against projects table
    storage/
      clickhouse.go                 # Buffered async writer (fire-and-forget)
      postgres.go                   # PostgreSQL reader (projects only)
    circuit/
      breaker.go                    # Per-detector circuit breakers
  proto/
    guard/v1/
      guard.proto                   # Symlinked from root proto/
  gen/
    guard/v1/
      guard.pb.go                   # Generated
      guard_grpc.pb.go              # Generated
  deploy/
    Dockerfile
  go.mod
  go.sum
```

### Sentry ML Engine Flow

```
CheckRequest arrives at Guard Edge Service
    |
    v
[Auth] Validate API key from gRPC metadata against projects table
    - project_id → mode (enforce/shadow), fail_open
    - Project row cached in-memory, refreshed every 30s
    |
    v
[Fan-Out] launch ALL hardcoded detectors as goroutines (PARALLEL)
    |
    +-- Prompt Injection detector  (20ms budget) — regex + heuristic patterns
    +-- Jailbreak detector         (20ms budget) — pattern matching
    +-- PII detector               (5ms budget)  — regex only, very fast
    +-- Content Moderation         (20ms budget) — keyword + pattern matching
    +-- Tool Abuse detector        (5ms budget)  — hardcoded allowed-list check
    |
    v
[Wait with Timeout] context.WithTimeout(25ms)
    - Collect all completed detector results
    - Detectors that didn't finish in time: treated as not triggered
    |
    v
[Aggregate] apply hardcoded threshold rules to detector results
    - ANY detector confidence >= 0.8 (hardcoded block threshold) → BLOCK
    - ANY detector triggered but below 0.8 → FLAG
    - All clear → ALLOW
    - If mode=shadow (from projects table) → override verdict to ALLOW, set is_shadow=true
    |
    v
[Fire-and-Forget] write security_event to ClickHouse
    - Async goroutine, NEVER blocks the hot path
    - Buffered writer: batch insert every 100ms or 1000 events
    |
    v
Return CheckResponse to SDK/Gateway
```

### Detector Interface

```go
// internal/engine/detector.go
type Detector interface {
    // Name returns the detector's identifier.
    Name() string

    // Category returns the threat category this detector covers.
    Category() ThreatCategory

    // Detect runs the detection logic. Must respect context deadline.
    Detect(ctx context.Context, req *DetectRequest) (*DetectResult, error)
}

type DetectRequest struct {
    Payload      string
    Action       ActionType
    Identity     *Identity
    ToolCall     *ToolCall
}

type DetectResult struct {
    Triggered  bool
    Confidence float32  // 0.0 - 1.0
    Details    string
}
```

### ClickHouse Writer

```go
// internal/storage/clickhouse.go
type SecurityEventsWriter struct {
    client  clickhouse.Conn
    buffer  chan *SecurityEvent  // Buffered channel, size 10000
    done    chan struct{}
}

func (w *SecurityEventsWriter) Write(event *SecurityEvent) {
    select {
    case w.buffer <- event:
        // Queued successfully
    default:
        // Buffer full — drop event, NEVER block the hot path
        metrics.DroppedEvents.Inc()
    }
}

// Background flusher: batch insert every 100ms or 1000 events
func (w *SecurityEventsWriter) flushLoop() {
    ticker := time.NewTicker(100 * time.Millisecond)
    batch := make([]*SecurityEvent, 0, 1000)
    for {
        select {
        case event := <-w.buffer:
            batch = append(batch, event)
            if len(batch) >= 1000 {
                w.flush(batch)
                batch = batch[:0]
            }
        case <-ticker.C:
            if len(batch) > 0 {
                w.flush(batch)
                batch = batch[:0]
            }
        case <-w.done:
            if len(batch) > 0 {
                w.flush(batch)
            }
            return
        }
    }
}
```

### Deployment: Separate ECS Service

The Guard service is a **separate ECS Fargate service** in the same cluster as the existing
FastAPI backend. They share the VPC and PostgreSQL database but are independently scalable.

```
ECS Cluster
  ├── triage-backend   (existing, Python/FastAPI, port 8000, ALB, HTTP)
  ├── triage-guard     (new, Go/gRPC, port 50051, NLB, gRPC+TLS)
  └── triage-gateway   (new Phase 2, Go/HTTP, port 443, ALB, HTTPS)
```

**Why separate services:**
- Different language (Go vs Python) — cannot share a process
- Different scaling profile (check volume vs webhook/code-indexing volume)
- Different protocol (gRPC vs HTTP)
- Failure isolation (Guard crash doesn't affect code indexing; code indexing crash doesn't affect enforcement)

---

## Part 4: Database Schema

### ClickHouse: `security_events`

The ONLY table Triage maintains for runtime data. One row per `check()` call or gateway
screening. This is an enforcement audit log, NOT a trace store.

```sql
CREATE TABLE security_events (
    -- Identity
    request_id          UUID DEFAULT generateUUIDv4(),
    project_id          String,
    timestamp           DateTime64(3, 'UTC'),

    -- What was checked
    action              Enum8(
        'llm_input' = 1, 'llm_output' = 2, 'tool_call' = 3, 'tool_result' = 4,
        'rag_retrieval' = 5, 'chain_of_thought' = 6, 'db_query' = 7, 'custom' = 8
    ),
    payload_preview     String,             -- First 500 chars (for dashboard display)
    payload_hash        FixedString(32),    -- SHA256 of full payload (for dedup)
    payload_size        UInt32,             -- Original payload size in bytes

    -- Verdict
    verdict             Enum8('allow' = 1, 'block' = 2, 'flag' = 3),
    is_shadow           UInt8,              -- 1 if shadow mode overrode the verdict
    reason              String,             -- Human-readable verdict explanation

    -- Detector results (parallel arrays — one entry per detector that ran)
    detector_names      Array(String),      -- ["prompt_injection_v2", "pii_ner"]
    detector_triggered  Array(UInt8),       -- [1, 0]
    detector_confidences Array(Float32),    -- [0.95, 0.12]
    detector_categories Array(String),      -- ["prompt_injection", "pii_leakage"]
    detector_details    Array(String),      -- ["Detected override attempt", ""]

    -- Identity (who triggered this action)
    user_id             String,
    session_id          String,
    tenant_id           String,

    -- Client correlation (so they can find this event in THEIR Datadog/LangSmith)
    client_trace_id     String,

    -- Tool call details (populated when action = tool_call)
    tool_name           String,
    tool_arguments      String,             -- JSON string

    -- Arbitrary metadata
    metadata            Map(String, String),

    -- Performance
    latency_ms          Float32,            -- Server-side processing time

    -- Source
    source              Enum8('sdk' = 1, 'gateway' = 2),
    sdk_language        String,             -- "python", "typescript", "go"
    sdk_version         String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (project_id, timestamp, request_id)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Secondary indexes for common dashboard queries
ALTER TABLE security_events ADD INDEX idx_verdict verdict TYPE set(3) GRANULARITY 4;
ALTER TABLE security_events ADD INDEX idx_action action TYPE set(8) GRANULARITY 4;
ALTER TABLE security_events ADD INDEX idx_user_id user_id TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE security_events ADD INDEX idx_is_shadow is_shadow TYPE set(2) GRANULARITY 4;
```

**Why ClickHouse, not PostgreSQL:**
- Security events are append-only, high-volume writes (potentially millions/day per customer)
- Dashboard queries are aggregation-heavy ("count all prompt injections last 7 days")
- ClickHouse columnar compression: repetitive fields compress 90%+
- Native TTL: auto-delete events older than 90 days
- Existing PostgreSQL (Supabase) would choke on this volume

### PostgreSQL: New table (via Drizzle in `parse/packages/db/`)

Only one new table for Phase 1. Detector configuration and policies are hardcoded in the
Guard service — no database-driven policy system yet.

**`projects`** — `parse/packages/db/src/schema/projects.ts`

```typescript
export const projects = pgTable('projects', {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    installationId: bigint('installation_id', { mode: 'number' })
        .references(() => installations.githubInstallationId),

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

**`policies` and `detectors` tables — deferred.** For Phase 1, all detector config
(which detectors run, thresholds, block/flag rules) is hardcoded in the Guard service
at `guard/internal/engine/defaults.go`. When we need per-project customization (Phase 3),
we add these tables and have the Guard service load them.

### What Happens to the Existing `traces` Table

- **Deprecate, do not delete.** Keep the table and `POST /v1/traces` endpoint alive.
- Add deprecation header to responses: `X-Triage-Deprecated: true`
- Stop writing once SDK v1 usage drops to zero.
- No migration to `security_events` — they are fundamentally different data.

---

## Part 5: Secure AI Gateway

New top-level directory: `gateway/`

```
gateway/
  cmd/
    gateway-server/
      main.go                     # HTTP server entrypoint
  internal/
    proxy/
      proxy.go                    # Core reverse proxy logic
      providers/
        openai.go                 # Parse OpenAI request/response format
        anthropic.go              # Parse Anthropic format
        generic.go                # Fallthrough for unknown providers
      router.go                   # Route to correct provider parser based on URL
    screening/
      screen.go                   # Extract payload → call Guard gRPC → decide
    auth/
      auth.go                     # Validate X-Triage-Key header against projects table
    config/
      config.go                   # Gateway configuration
  deploy/
    Dockerfile
  go.mod
```

### Gateway Request Flow

```
Client → gateway.triage.dev/v1/chat/completions
    |
    v
[Auth] Extract X-Triage-Key header → validate against projects table
    |
    v
[Identify Provider] from URL path:
    /v1/chat/completions     → OpenAI
    /v1/messages             → Anthropic
    |
    v
[Parse Request] provider-specific parser extracts messages, model, tools
    |
    v
[Screen Input] Guard.Check(payload=user_messages, action=LLM_INPUT)
    |
    +-- BLOCKED → return 403 {"error": {"type": "blocked", "request_id": "..."}}
    +-- ALLOWED → continue
    |
    v
[Forward to Provider] swap Triage key for provider key, proxy request
    |
    v
[Receive Response] from api.openai.com / api.anthropic.com
    |
    v
[Screen Output] Guard.Check(payload=completion_text, action=LLM_OUTPUT)
    |
    +-- BLOCKED → return 403 (for PII leakage in outputs)
    +-- ALLOWED → return original provider response to client
```

**Streaming (Phase 2):** Buffer-then-screen — accumulate full SSE response, screen after
completion. If blocked, return a final SSE event with the block notice.

**Streaming (Phase 3):** Real-time token screening — periodically screen accumulated tokens
mid-stream and terminate early if threat detected.

---

## Part 6: Dashboard Changes

The existing dashboard at `parse/apps/web/` is already security-focused (findings inbox, rules
builder, remediation queue). We add runtime enforcement views.

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
    custom-rules-editor.tsx       # Regex/keyword/classifier rule composer
  project/
    project-settings.tsx          # Project creation, API key management
    integration-guide.tsx         # Setup instructions for SDK + Gateway
```

### New API Routes

```
/review/runtime                   # Runtime security events page
/review/policy                    # Policy configuration page
/api/guard/events                 # Query ClickHouse for security events
/api/guard/analytics              # Aggregated threat analytics
/api/guard/projects               # Project CRUD
/api/guard/policies               # Policy CRUD
```

### Key Dashboard Queries (ClickHouse)

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

-- Shadow mode report ("what would have been blocked")
SELECT count() as total,
       countIf(verdict = 'block') as would_block,
       countIf(verdict = 'flag') as would_flag
FROM security_events
WHERE project_id = ? AND is_shadow = 1 AND timestamp > now() - INTERVAL 7 DAY;

-- Top flagged users
SELECT user_id, count() as events,
       countIf(verdict = 'block') as blocks
FROM security_events
WHERE project_id = ? AND verdict IN ('block', 'flag')
GROUP BY user_id ORDER BY blocks DESC LIMIT 20;

-- Enforcement latency percentiles
SELECT quantiles(0.5, 0.95, 0.99)(latency_ms)
FROM security_events
WHERE project_id = ? AND timestamp > now() - INTERVAL 1 DAY;
```

---

## Part 7: Shadow Mode

Shadow mode does NOT require a separate ingestion pipeline. The same Gateway/SDK → Guard →
ClickHouse pipeline is used with a different enforcement toggle.

1. Client integrates via Gateway or SDK `check()` — identical setup to enforce mode
2. Payload hits Guard service, Sentry ML evaluates all detectors normally
3. If `mode=shadow`: verdict is overridden to ALLOW regardless of detector results
4. The `security_event` row is written with `is_shadow=1` and the **real** verdict
5. Client's application is never blocked — zero impact on their production
6. Dashboard shows "would have blocked" report with real detector results

**Going live:** Flip `mode` from `"shadow"` to `"enforce"` in project settings. That's it.
No code changes, no deployment, no migration.

---

## Part 8: Client Observability Export

We push security events TO the client's observability stack. We do NOT pull their traces.

**Webhook (Phase 4):** POST security event JSON to a client-configured URL on BLOCK/FLAG events.
Configured per-project in the dashboard.

**OTel export (Phase 4):** Emit security events as OpenTelemetry spans to the client's OTel
collector endpoint. The span contains the verdict, detector results, and the client's
`trace_id` so they can correlate with their existing traces.

**Datadog integration (Phase 4):** Push events via Datadog Events API with tags for severity,
threat category, and user ID.

---

## Part 9: Migration Strategy

### SDK v1 → v2

The new SDK v2 replaces the existing code in `sdk/python/`, `sdk/typescript/`, `sdk/go/`.
The v1 code is preserved in git history and on existing PyPI/npm releases.

- **v2 is a breaking change.** Different API surface, different dependencies, different purpose.
- The package name stays the same (`triage-sdk` on PyPI, `@triage-sec/sdk` on npm).
- v1.x gets no new features. Security patches only. Deprecation warning in `init()`.

### `POST /v1/traces` Endpoint

Keep alive with a deprecation header. Do not delete.

```python
@router.post("/v1/traces")
async def receive_traces(request: Request) -> Response:
    # Still process for backward compatibility
    response = await _existing_logic(request)
    response.headers["X-Triage-Deprecated"] = "true"
    response.headers["X-Triage-Upgrade"] = "https://docs.triage.dev/upgrade-to-v2"
    return response
```

### `traces` Table

Keep in PostgreSQL. Do not migrate to ClickHouse. Do not delete.
Stop writing when SDK v1 traffic drops to zero.

---

## Implementation Phases

### Phase 1: Core Enforcement (Weeks 1-4)

**Goal:** `pip install triage-sdk && triage.check()` returns BLOCK/ALLOW in <40ms.

| Step | What | Where |
|------|------|-------|
| 1.1 | Proto definition + code generation (Go, Python, TS) | `proto/guard/v1/guard.proto` |
| 1.2 | Guard Edge Service scaffold (gRPC server, stub Check) | `guard/` |
| 1.3 | Python SDK v2 (config, client, check, types, circuit breaker) | `sdk/python/` |
| 1.4 | Hardcoded detectors (prompt injection regex + PII regex) | `guard/internal/engine/` |
| 1.5 | PostgreSQL schema (projects table only, via Drizzle) | `parse/packages/db/` |
| 1.6 | API key validation + project auth in Guard service | `guard/internal/auth/` |
| 1.7 | End-to-end integration test + latency benchmark | `guard/tests/`, `sdk/python/tests/` |
| 1.8 | TypeScript SDK v2 | `sdk/typescript/` |

### Phase 2: Gateway + ClickHouse + Dashboard (Weeks 5-8)

**Goal:** Zero-code gateway integration and a dashboard showing security events.

| Step | What | Where |
|------|------|-------|
| 2.1 | ClickHouse setup + `security_events` table | `guard/internal/storage/` |
| 2.2 | Buffered ClickHouse writer in Guard service | `guard/internal/storage/clickhouse.go` |
| 2.3 | Secure AI Gateway (OpenAI + Anthropic providers) | `gateway/` |
| 2.4 | Dashboard: security events table + event detail | `parse/apps/web/components/guard/` |
| 2.5 | Dashboard: policy configuration UI | `parse/apps/web/components/policy/` |
| 2.6 | Go SDK v2 | `sdk/go/` |
| 2.7 | CDK deployment (Guard ECS + NLB, Gateway ECS + ALB) | `guard/deploy/`, `gateway/deploy/` |

### Phase 3: Framework Integrations + Advanced Detectors (Weeks 9-12)

**Goal:** Drop-in framework integrations and ML-based detectors.

| Step | What | Where |
|------|------|-------|
| 3.1 | LangChain callback, CrewAI middleware, Vercel AI hook | `sdk/*/integrations/` |
| 3.2 | ML-based detectors (replace heuristics with classifiers) | `guard/internal/engine/detectors/` |
| 3.3 | Custom rules engine (regex, keyword, classifier per-project) | `guard/internal/engine/detectors/custom_rule.go` |
| 3.4 | Dashboard: threat analytics + latency charts | `parse/apps/web/components/guard/` |
| 3.5 | CheckBatch RPC for parallel payload screening | `proto/`, `guard/`, `sdk/` |

### Phase 4: Shadow Mode Polish + Client Export (Weeks 13-16)

**Goal:** Production-ready shadow mode and push security events to client observability.

| Step | What | Where |
|------|------|-------|
| 4.1 | Shadow mode report dashboard | `parse/apps/web/components/guard/` |
| 4.2 | Webhook push (security events → client's URL) | `guard/internal/export/` |
| 4.3 | OTel export (security events → client's collector) | `guard/internal/export/` |
| 4.4 | Real-time streaming token screening in Gateway | `gateway/internal/proxy/` |
| 4.5 | Deprecate SDK v1 + `POST /v1/traces` endpoint | `sdk/`, `backend/` |

---

## Critical Files

### Replace (SDK v1 → v2)

| File | Change |
|------|--------|
| `sdk/python/src/triage_sdk/sdk.py` | Rewrite: Traceloop init → gRPC client init |
| `sdk/python/src/triage_sdk/config.py` | Rewrite: remove OTel config, add project_id/mode/timeout |
| `sdk/python/src/triage_sdk/context.py` | Remove: no more OTel context propagation |
| `sdk/python/src/triage_sdk/processor.py` | Remove: no more span processor |
| `sdk/python/src/triage_sdk/constants.py` | Simplify: just env var names |
| `sdk/python/pyproject.toml` | Remove traceloop/otel deps, add grpcio/protobuf |

### Create (New Services)

| File/Directory | Purpose |
|----------------|---------|
| `proto/guard/v1/guard.proto` | Shared protobuf definition |
| `guard/` | Go Guard edge service (gRPC) |
| `gateway/` | Go Secure AI Gateway (HTTP reverse proxy) |

### Extend (Database Schema)

| File | Change |
|------|--------|
| `parse/packages/db/src/schema/projects.ts` | New `projects` table |
| `parse/packages/db/src/schema/index.ts` | Export new table schema |

### Deprecate (Keep, Mark)

| File | Change |
|------|--------|
| `backend/src/triage/routes/traces.py` | Add deprecation header to responses |
| `backend/src/triage/models/db/trace.py` | No changes, stop writing eventually |

### Extend (Dashboard)

| Directory | Purpose |
|-----------|---------|
| `parse/apps/web/src/components/guard/` | Runtime security event views |
| `parse/apps/web/src/components/policy/` | Policy configuration UI |
| `parse/apps/web/src/components/project/` | Project/API key management |

---

## Verification Checklist

### Phase 1
- [ ] Guard service starts: `cd guard && go run cmd/guard-server/main.go`
- [ ] Python SDK tests pass: `cd sdk/python && poetry run pytest tests/ -x`
- [ ] End-to-end: Python SDK `check()` → Guard → verdict returned
- [ ] Latency: `check()` < 40ms on loopback
- [ ] Circuit breaker: kill Guard, SDK returns fail-open Decision
- [ ] Existing backend unaffected: `cd backend && make check`

### Phase 2
- [ ] Gateway screens OpenAI request: `curl -H "X-Triage-Key: tsk_..." gateway.triage.dev/v1/chat/completions`
- [ ] Security event in ClickHouse within 200ms
- [ ] Dashboard displays event at `/review/runtime`
- [ ] Policy change in dashboard → Guard picks up within 30s
