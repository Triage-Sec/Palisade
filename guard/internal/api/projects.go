package api

import (
	"database/sql"
	"net/http"

	"github.com/triage-ai/palisade/internal/store"
	"go.uber.org/zap"
)

func (d *Dependencies) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req CreateProjectReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "Invalid JSON body"})
		return
	}
	if req.Name == "" || len(req.Name) > 255 {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "name must be 1-255 characters"})
		return
	}

	project, _, plainKey, err := d.Store.CreateProject(r.Context(), req.Name)
	if err != nil {
		d.Logger.Error("failed to create project", zapError(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to create project"})
		return
	}

	writeJSON(w, http.StatusCreated, CreateProjectResp{
		ID:             project.ID,
		Name:           project.Name,
		APIKey:         plainKey,
		APIKeyPrefix:   project.APIKeyPrefix,
		Mode:           project.Mode,
		FailOpen:       project.FailOpen,
		ChecksPerMonth: project.ChecksPerMonth,
		CreatedAt:      project.CreatedAt,
	})
}

func (d *Dependencies) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := d.Store.ListProjects(r.Context())
	if err != nil {
		d.Logger.Error("failed to list projects", zapError(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to list projects"})
		return
	}

	resp := make([]ProjectResp, 0, len(projects))
	for _, p := range projects {
		resp = append(resp, projectToResp(p))
	}
	writeJSON(w, http.StatusOK, resp)
}

func (d *Dependencies) handleGetProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("project_id")
	project, err := d.Store.GetProject(r.Context(), id)
	if err != nil {
		d.Logger.Error("failed to get project", zapError(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to get project"})
		return
	}
	if project == nil {
		writeJSON(w, http.StatusNotFound, ErrorResp{Detail: "Project not found."})
		return
	}
	writeJSON(w, http.StatusOK, projectToResp(project))
}

func (d *Dependencies) handleUpdateProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("project_id")

	var req UpdateProjectReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "Invalid JSON body"})
		return
	}

	// Validate name if provided
	if req.Name != nil && (len(*req.Name) == 0 || len(*req.Name) > 255) {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "name must be 1-255 characters"})
		return
	}

	// Validate mode if provided
	if req.Mode != nil && *req.Mode != "enforce" && *req.Mode != "shadow" {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "mode must be 'enforce' or 'shadow'"})
		return
	}

	project, err := d.Store.UpdateProject(r.Context(), id, store.UpdateProjectParams{
		Name:           req.Name,
		Mode:           req.Mode,
		FailOpen:       req.FailOpen,
		ChecksPerMonth: req.ChecksPerMonth,
	})
	if err != nil {
		d.Logger.Error("failed to update project", zapError(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to update project"})
		return
	}
	if project == nil {
		writeJSON(w, http.StatusNotFound, ErrorResp{Detail: "Project not found."})
		return
	}
	writeJSON(w, http.StatusOK, projectToResp(project))
}

func (d *Dependencies) handleDeleteProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("project_id")
	err := d.Store.DeleteProject(r.Context(), id)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, ErrorResp{Detail: "Project not found."})
		return
	}
	if err != nil {
		d.Logger.Error("failed to delete project", zapError(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to delete project"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d *Dependencies) handleRotateKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("project_id")
	project, plainKey, err := d.Store.RotateAPIKey(r.Context(), id)
	if err != nil {
		d.Logger.Error("failed to rotate key", zapError(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to rotate API key"})
		return
	}
	writeJSON(w, http.StatusOK, RotateKeyResp{
		APIKey:       plainKey,
		APIKeyPrefix: project.APIKeyPrefix,
	})
}

func projectToResp(p *store.Project) ProjectResp {
	return ProjectResp{
		ID:             p.ID,
		Name:           p.Name,
		APIKeyPrefix:   p.APIKeyPrefix,
		Mode:           p.Mode,
		FailOpen:       p.FailOpen,
		ChecksPerMonth: p.ChecksPerMonth,
		CreatedAt:      p.CreatedAt,
		UpdatedAt:      p.UpdatedAt,
	}
}

// zapError is a helper to create a zap field from an error.
func zapError(err error) zap.Field {
	return zap.Error(err)
}
