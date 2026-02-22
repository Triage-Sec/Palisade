CREATE TABLE IF NOT EXISTS security_events (
    -- Identity
    request_id          UUID DEFAULT generateUUIDv4(),
    project_id          String,
    timestamp           DateTime64(3, 'UTC'),

    -- What was checked
    action              Enum8(
        'llm_input' = 1, 'llm_output' = 2, 'tool_call' = 3, 'tool_result' = 4,
        'rag_retrieval' = 5, 'chain_of_thought' = 6, 'db_query' = 7, 'custom' = 8
    ),
    payload_preview     String,
    payload_hash        FixedString(32),
    payload_size        UInt32,

    -- Verdict
    verdict             Enum8('allow' = 1, 'block' = 2, 'flag' = 3),
    is_shadow           UInt8,
    reason              String,

    -- Detector results (parallel arrays)
    detector_names      Array(String),
    detector_triggered  Array(UInt8),
    detector_confidences Array(Float32),
    detector_categories Array(String),
    detector_details    Array(String),

    -- Identity context
    user_id             String,
    session_id          String,
    tenant_id           String,
    client_trace_id     String,

    -- Tool call details
    tool_name           String,
    tool_arguments      String,

    -- Metadata
    metadata            Map(String, String),

    -- Performance
    latency_ms          Float32,

    -- Source tracking
    source              Enum8('sdk' = 1, 'gateway' = 2),
    sdk_language        String,
    sdk_version         String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (project_id, timestamp, request_id)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

ALTER TABLE security_events ADD INDEX IF NOT EXISTS idx_verdict verdict TYPE set(3) GRANULARITY 4;
ALTER TABLE security_events ADD INDEX IF NOT EXISTS idx_action action TYPE set(8) GRANULARITY 4;
ALTER TABLE security_events ADD INDEX IF NOT EXISTS idx_user_id user_id TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE security_events ADD INDEX IF NOT EXISTS idx_is_shadow is_shadow TYPE set(2) GRANULARITY 4;
