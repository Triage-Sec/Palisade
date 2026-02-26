package registry

import "context"

// ToolRegistry provides tool definitions for a project.
type ToolRegistry interface {
	// GetTool returns the ToolDefinition for a project+tool pair.
	// Returns nil if the tool is not registered (unregistered tool path).
	GetTool(ctx context.Context, projectID, toolName string) (*ToolDefinition, error)
}
