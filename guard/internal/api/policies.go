package api

import (
	"encoding/json"
	"net/http"

	"github.com/triage-ai/palisade/internal/store"
	"go.uber.org/zap"
)

func (d *Dependencies) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	policy, err := d.Store.GetPolicy(r.Context(), projectID)
	if err != nil {
		d.Logger.Error("failed to get policy", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to get policy"})
		return
	}
	if policy == nil {
		writeJSON(w, http.StatusNotFound, ErrorResp{Detail: "Policy not found."})
		return
	}
	writeJSON(w, http.StatusOK, policyToResp(policy))
}

func (d *Dependencies) handleReplacePolicy(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")

	var req UpdatePolicyReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "Invalid JSON body"})
		return
	}

	dc := req.DetectorConfig
	if dc == nil {
		dc = json.RawMessage(`{}`)
	}

	policy, err := d.Store.ReplacePolicy(r.Context(), projectID, store.ReplacePolicyParams{
		DetectorConfig:  dc,
		CustomBlocklist: req.CustomBlocklist,
	})
	if err != nil {
		d.Logger.Error("failed to replace policy", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to replace policy"})
		return
	}
	if policy == nil {
		writeJSON(w, http.StatusNotFound, ErrorResp{Detail: "Policy not found."})
		return
	}
	writeJSON(w, http.StatusOK, policyToResp(policy))
}

func (d *Dependencies) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")

	var req UpdatePolicyReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "Invalid JSON body"})
		return
	}

	params := store.UpdatePolicyParams{}
	if req.DetectorConfig != nil {
		params.DetectorConfig = &req.DetectorConfig
	}
	if req.CustomBlocklist != nil {
		params.CustomBlocklist = &req.CustomBlocklist
	}

	policy, err := d.Store.UpdatePolicy(r.Context(), projectID, params)
	if err != nil {
		d.Logger.Error("failed to update policy", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to update policy"})
		return
	}
	if policy == nil {
		writeJSON(w, http.StatusNotFound, ErrorResp{Detail: "Policy not found."})
		return
	}
	writeJSON(w, http.StatusOK, policyToResp(policy))
}

func policyToResp(p *store.Policy) PolicyResp {
	dc := p.DetectorConfig
	if dc == nil {
		dc = json.RawMessage(`{}`)
	}
	return PolicyResp{
		ID:              p.ID,
		ProjectID:       p.ProjectID,
		DetectorConfig:  dc,
		CustomBlocklist: p.CustomBlocklist,
		CreatedAt:       p.CreatedAt,
		UpdatedAt:       p.UpdatedAt,
	}
}
