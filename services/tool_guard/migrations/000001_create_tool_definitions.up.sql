CREATE TABLE IF NOT EXISTS tool_definitions (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id            UUID REFERENCES projects(id) ON DELETE CASCADE NOT NULL,
    tool_name             TEXT NOT NULL,
    description           TEXT,
    risk_tier             TEXT NOT NULL DEFAULT 'read',
    requires_confirmation BOOLEAN NOT NULL DEFAULT false,
    preconditions         JSONB NOT NULL DEFAULT '[]',
    argument_schema       JSONB,
    argument_policy       JSONB NOT NULL DEFAULT '{}',
    contextual_rules      JSONB NOT NULL DEFAULT '{}',
    information_flow      JSONB NOT NULL DEFAULT '{}',
    created_at            TIMESTAMP DEFAULT now(),
    updated_at            TIMESTAMP DEFAULT now(),
    UNIQUE(project_id, tool_name)
);

CREATE INDEX idx_tool_definitions_project_id ON tool_definitions(project_id);
CREATE INDEX idx_tool_definitions_project_tool ON tool_definitions(project_id, tool_name);
