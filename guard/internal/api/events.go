package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/triage-ai/palisade/internal/chread"
	"go.uber.org/zap"
)

func (d *Dependencies) handleListEvents(w http.ResponseWriter, r *http.Request) {
	if d.Reader == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResp{Detail: "ClickHouse not configured"})
		return
	}

	q := r.URL.Query()
	projectID := q.Get("project_id")
	if projectID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "project_id query parameter is required"})
		return
	}

	params := chread.ListEventsParams{
		ProjectID: projectID,
		Page:      queryInt(q, "page", 1),
		PageSize:  queryInt(q, "page_size", 50),
	}
	if params.PageSize > 200 {
		params.PageSize = 200
	}
	if params.Page < 1 {
		params.Page = 1
	}

	if v := q.Get("verdict"); v != "" {
		params.Verdict = &v
	}
	if v := q.Get("action"); v != "" {
		params.Action = &v
	}
	if v := q.Get("user_id"); v != "" {
		params.UserID = &v
	}
	if v := q.Get("category"); v != "" {
		params.Category = &v
	}
	if v := q.Get("is_shadow"); v != "" {
		b := v == "true" || v == "1"
		params.IsShadow = &b
	}
	if v := q.Get("start_time"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.StartTime = &t
		}
	}
	if v := q.Get("end_time"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			params.EndTime = &t
		}
	}

	events, total, err := d.Reader.ListEvents(r.Context(), params)
	if err != nil {
		d.Logger.Error("failed to list events", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to list events"})
		return
	}

	resp := EventListResp{
		Events:   make([]SecurityEventResp, 0, len(events)),
		Total:    total,
		Page:     params.Page,
		PageSize: params.PageSize,
	}
	for _, e := range events {
		resp.Events = append(resp.Events, eventRowToResp(e))
	}

	writeJSON(w, http.StatusOK, resp)
}

func (d *Dependencies) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	if d.Reader == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResp{Detail: "ClickHouse not configured"})
		return
	}

	requestID := r.PathValue("request_id")
	projectID := r.URL.Query().Get("project_id")
	if projectID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "project_id query parameter is required"})
		return
	}

	event, err := d.Reader.GetEvent(r.Context(), projectID, requestID)
	if err != nil {
		d.Logger.Error("failed to get event", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to get event"})
		return
	}
	if event == nil {
		writeJSON(w, http.StatusNotFound, ErrorResp{Detail: "Event not found."})
		return
	}

	writeJSON(w, http.StatusOK, eventRowToResp(*event))
}

func (d *Dependencies) handleGetAnalytics(w http.ResponseWriter, r *http.Request) {
	if d.Reader == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResp{Detail: "ClickHouse not configured"})
		return
	}

	q := r.URL.Query()
	projectID := q.Get("project_id")
	if projectID == "" {
		writeJSON(w, http.StatusBadRequest, ErrorResp{Detail: "project_id query parameter is required"})
		return
	}

	days := queryInt(q, "days", 7)
	if days < 1 {
		days = 1
	}
	if days > 90 {
		days = 90
	}

	result, err := d.Reader.GetAnalytics(r.Context(), projectID, days)
	if err != nil {
		d.Logger.Error("failed to get analytics", zap.Error(err))
		writeJSON(w, http.StatusInternalServerError, ErrorResp{Detail: "Failed to get analytics"})
		return
	}

	writeJSON(w, http.StatusOK, AnalyticsResp{
		Summary: SummaryStatsResp{
			TotalChecks: result.Summary.TotalChecks,
			Blocks:      result.Summary.Blocks,
			Flags:       result.Summary.Flags,
			Allows:      result.Summary.Allows,
		},
		BlocksOverTime: toTimeSeriesResp(result.BlocksOverTime),
		TopCategories:  toCategoryResp(result.TopCategories),
		ShadowReport: ShadowReportResp{
			Total:      result.ShadowReport.Total,
			WouldBlock: result.ShadowReport.WouldBlock,
			WouldFlag:  result.ShadowReport.WouldFlag,
		},
		LatencyPercentiles: LatencyPercentilesResp{
			P50: result.LatencyPercentiles.P50,
			P95: result.LatencyPercentiles.P95,
			P99: result.LatencyPercentiles.P99,
		},
		TopFlaggedUsers: toUserCountResp(result.TopFlaggedUsers),
	})
}

// eventRowToResp converts a ClickHouse EventRow to the API response.
// Detector results are stored as parallel arrays and reconstructed here.
func eventRowToResp(e chread.EventRow) SecurityEventResp {
	detectors := make([]DetectorResultResp, 0, len(e.DetectorNames))
	for i, name := range e.DetectorNames {
		var triggered bool
		if i < len(e.DetectorTriggered) {
			triggered = e.DetectorTriggered[i] == 1
		}
		var confidence float32
		if i < len(e.DetectorConfidences) {
			confidence = e.DetectorConfidences[i]
		}
		cat := "unspecified"
		if i < len(e.DetectorCategories) && e.DetectorCategories[i] != "" {
			cat = e.DetectorCategories[i]
		}
		var details *string
		if i < len(e.DetectorDetails) && e.DetectorDetails[i] != "" {
			d := e.DetectorDetails[i]
			details = &d
		}
		detectors = append(detectors, DetectorResultResp{
			Detector:   name,
			Triggered:  triggered,
			Confidence: confidence,
			Category:   cat,
			Details:    details,
		})
	}

	var reason *string
	if e.Reason != "" {
		reason = &e.Reason
	}

	return SecurityEventResp{
		RequestID:     e.RequestID,
		ProjectID:     e.ProjectID,
		Action:        e.Action,
		Verdict:       e.Verdict,
		IsShadow:      e.IsShadow == 1,
		Reason:        reason,
		Detectors:     detectors,
		UserID:        nilIfEmpty(e.UserID),
		SessionID:     nilIfEmpty(e.SessionID),
		TenantID:      nilIfEmpty(e.TenantID),
		ClientTraceID: nilIfEmpty(e.ClientTraceID),
		ToolName:      nilIfEmpty(e.ToolName),
		ToolArguments: nilIfEmpty(e.ToolArguments),
		LatencyMs:     e.LatencyMs,
		Source:        e.Source,
		Timestamp:     e.Timestamp,
	}
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func queryInt(q interface{ Get(string) string }, key string, defaultVal int) int {
	v := q.(interface{ Get(string) string }).Get(key)
	if v == "" {
		return defaultVal
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return i
}

func toTimeSeriesResp(buckets []chread.TimeSeriesBucket) []TimeSeriesBucketResp {
	out := make([]TimeSeriesBucketResp, len(buckets))
	for i, b := range buckets {
		out[i] = TimeSeriesBucketResp{Hour: b.Hour, Count: b.Count}
	}
	return out
}

func toCategoryResp(cats []chread.CategoryCount) []CategoryCountResp {
	out := make([]CategoryCountResp, len(cats))
	for i, c := range cats {
		out[i] = CategoryCountResp{Category: c.Category, Count: c.Count}
	}
	return out
}

func toUserCountResp(users []chread.UserCount) []UserCountResp {
	out := make([]UserCountResp, len(users))
	for i, u := range users {
		out[i] = UserCountResp{UserID: u.UserID, Count: u.Count}
	}
	return out
}
