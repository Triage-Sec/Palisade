package chread

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
)

// Reader provides read access to the ClickHouse security_events table.
type Reader struct {
	conn   driver.Conn
	logger *zap.Logger
}

// NewReader opens a ClickHouse connection for read queries.
func NewReader(dsn string, logger *zap.Logger) (*Reader, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("NewReader: %w", err)
	}
	if opts.TLS == nil {
		opts.TLS = &tls.Config{}
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("NewReader: %w", err)
	}
	if err := conn.Ping(context.Background()); err != nil {
		return nil, fmt.Errorf("NewReader: %w", err)
	}

	return &Reader{conn: conn, logger: logger}, nil
}

// Close closes the ClickHouse connection.
func (r *Reader) Close() error {
	return r.conn.Close()
}

// EventRow represents a single row from the security_events table.
type EventRow struct {
	RequestID           string
	ProjectID           string
	Timestamp           time.Time
	Action              string
	PayloadPreview      string
	Verdict             string
	IsShadow            uint8
	Reason              string
	DetectorNames       []string
	DetectorTriggered   []uint8
	DetectorConfidences []float32
	DetectorCategories  []string
	DetectorDetails     []string
	UserID              string
	SessionID           string
	TenantID            string
	ClientTraceID       string
	ToolName            string
	ToolArguments       string
	LatencyMs           float32
	Source              string
}

// ListEventsParams holds filters and pagination for event listing.
type ListEventsParams struct {
	ProjectID string
	Verdict   *string
	Action    *string
	UserID    *string
	Category  *string
	IsShadow  *bool
	StartTime *time.Time
	EndTime   *time.Time
	Page      int
	PageSize  int
}

// ListEvents returns paginated, filtered security events and the total count.
func (r *Reader) ListEvents(ctx context.Context, params ListEventsParams) ([]EventRow, int, error) {
	conditions := []string{"project_id = @project_id"}
	args := []any{
		clickhouse.Named("project_id", params.ProjectID),
	}

	if params.Verdict != nil {
		conditions = append(conditions, "verdict = @verdict")
		args = append(args, clickhouse.Named("verdict", *params.Verdict))
	}
	if params.Action != nil {
		conditions = append(conditions, "action = @action")
		args = append(args, clickhouse.Named("action", *params.Action))
	}
	if params.UserID != nil {
		conditions = append(conditions, "user_id = @user_id")
		args = append(args, clickhouse.Named("user_id", *params.UserID))
	}
	if params.Category != nil {
		conditions = append(conditions, "has(detector_categories, @category)")
		args = append(args, clickhouse.Named("category", *params.Category))
	}
	if params.IsShadow != nil {
		var v uint8
		if *params.IsShadow {
			v = 1
		}
		conditions = append(conditions, "is_shadow = @is_shadow")
		args = append(args, clickhouse.Named("is_shadow", v))
	}
	if params.StartTime != nil {
		conditions = append(conditions, "timestamp >= @start_time")
		args = append(args, clickhouse.Named("start_time", *params.StartTime))
	}
	if params.EndTime != nil {
		conditions = append(conditions, "timestamp <= @end_time")
		args = append(args, clickhouse.Named("end_time", *params.EndTime))
	}

	where := strings.Join(conditions, " AND ")
	offset := (params.Page - 1) * params.PageSize

	// Count query
	var total uint64
	countQuery := fmt.Sprintf("SELECT count() FROM security_events WHERE %s", where)
	if err := r.conn.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ListEvents count: %w", err)
	}

	// Data query
	dataQuery := fmt.Sprintf(
		"SELECT request_id, project_id, timestamp, action, payload_preview, verdict, "+
			"is_shadow, reason, "+
			"detector_names, detector_triggered, detector_confidences, detector_categories, detector_details, "+
			"user_id, session_id, tenant_id, client_trace_id, "+
			"tool_name, tool_arguments, latency_ms, source "+
			"FROM security_events WHERE %s "+
			"ORDER BY timestamp DESC "+
			"LIMIT @limit OFFSET @offset",
		where,
	)
	args = append(args,
		clickhouse.Named("limit", uint32(params.PageSize)),
		clickhouse.Named("offset", uint32(offset)),
	)

	rows, err := r.conn.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("ListEvents query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var events []EventRow
	for rows.Next() {
		var e EventRow
		if err := rows.Scan(
			&e.RequestID, &e.ProjectID, &e.Timestamp, &e.Action, &e.PayloadPreview,
			&e.Verdict, &e.IsShadow, &e.Reason,
			&e.DetectorNames, &e.DetectorTriggered, &e.DetectorConfidences,
			&e.DetectorCategories, &e.DetectorDetails,
			&e.UserID, &e.SessionID, &e.TenantID, &e.ClientTraceID,
			&e.ToolName, &e.ToolArguments, &e.LatencyMs, &e.Source,
		); err != nil {
			return nil, 0, fmt.Errorf("ListEvents scan: %w", err)
		}
		events = append(events, e)
	}

	return events, int(total), rows.Err()
}

// GetEvent returns a single event by project ID and request ID, or nil if not found.
func (r *Reader) GetEvent(ctx context.Context, projectID, requestID string) (*EventRow, error) {
	row := r.conn.QueryRow(ctx,
		"SELECT request_id, project_id, timestamp, action, payload_preview, verdict, "+
			"is_shadow, reason, "+
			"detector_names, detector_triggered, detector_confidences, detector_categories, detector_details, "+
			"user_id, session_id, tenant_id, client_trace_id, "+
			"tool_name, tool_arguments, latency_ms, source "+
			"FROM security_events "+
			"WHERE project_id = @project_id AND request_id = @request_id",
		clickhouse.Named("project_id", projectID),
		clickhouse.Named("request_id", requestID),
	)

	var e EventRow
	if err := row.Scan(
		&e.RequestID, &e.ProjectID, &e.Timestamp, &e.Action, &e.PayloadPreview,
		&e.Verdict, &e.IsShadow, &e.Reason,
		&e.DetectorNames, &e.DetectorTriggered, &e.DetectorConfidences,
		&e.DetectorCategories, &e.DetectorDetails,
		&e.UserID, &e.SessionID, &e.TenantID, &e.ClientTraceID,
		&e.ToolName, &e.ToolArguments, &e.LatencyMs, &e.Source,
	); err != nil {
		// ClickHouse doesn't return sql.ErrNoRows, so check for empty result
		return nil, fmt.Errorf("GetEvent: %w", err)
	}
	if e.RequestID == "" {
		return nil, nil
	}
	return &e, nil
}

// SummaryStats holds aggregate counts.
type SummaryStats struct {
	TotalChecks int `json:"total_checks"`
	Blocks      int `json:"blocks"`
	Flags       int `json:"flags"`
	Allows      int `json:"allows"`
}

// TimeSeriesBucket holds an hourly count.
type TimeSeriesBucket struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// CategoryCount holds a category and its count.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// ShadowReportStats holds shadow mode analysis.
type ShadowReportStats struct {
	Total      int `json:"total"`
	WouldBlock int `json:"would_block"`
	WouldFlag  int `json:"would_flag"`
}

// LatencyStats holds latency percentiles.
type LatencyStats struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
}

// UserCount holds a user_id and its count.
type UserCount struct {
	UserID string `json:"user_id"`
	Count  int    `json:"count"`
}

// AnalyticsResult holds all analytics aggregations.
type AnalyticsResult struct {
	Summary            SummaryStats       `json:"summary"`
	BlocksOverTime     []TimeSeriesBucket `json:"blocks_over_time"`
	TopCategories      []CategoryCount    `json:"top_categories"`
	ShadowReport       ShadowReportStats  `json:"shadow_report"`
	LatencyPercentiles LatencyStats       `json:"latency_percentiles"`
	TopFlaggedUsers    []UserCount        `json:"top_flagged_users"`
}

// GetAnalytics returns aggregated analytics for a project over the given number of days.
func (r *Reader) GetAnalytics(ctx context.Context, projectID string, days int) (*AnalyticsResult, error) {
	now := time.Now().UTC()
	rangeStart := now.Add(-time.Duration(days) * 24 * time.Hour)
	dayStart := now.Add(-24 * time.Hour)

	baseArgs := []any{
		clickhouse.Named("project_id", projectID),
		clickhouse.Named("range_start", rangeStart),
	}

	result := &AnalyticsResult{}

	// Summary counts
	var totalChecks, blocks, flags, allows uint64
	err := r.conn.QueryRow(ctx,
		"SELECT count() as total_checks, "+
			"countIf(verdict = 'block') as blocks, "+
			"countIf(verdict = 'flag') as flags, "+
			"countIf(verdict = 'allow') as allows "+
			"FROM security_events "+
			"WHERE project_id = @project_id AND timestamp >= @range_start",
		baseArgs...,
	).Scan(&totalChecks, &blocks, &flags, &allows)
	if err != nil {
		return nil, fmt.Errorf("GetAnalytics summary: %w", err)
	}
	result.Summary = SummaryStats{
		TotalChecks: int(totalChecks),
		Blocks:      int(blocks),
		Flags:       int(flags),
		Allows:      int(allows),
	}

	// Blocks over time (hourly)
	botRows, err := r.conn.Query(ctx,
		"SELECT toStartOfHour(timestamp) as hour, count() as count "+
			"FROM security_events "+
			"WHERE project_id = @project_id AND verdict = 'block' "+
			"AND timestamp >= @range_start "+
			"GROUP BY hour ORDER BY hour",
		baseArgs...,
	)
	if err != nil {
		return nil, fmt.Errorf("GetAnalytics blocks_over_time: %w", err)
	}
	defer func() { _ = botRows.Close() }()
	for botRows.Next() {
		var hour time.Time
		var count uint64
		if err := botRows.Scan(&hour, &count); err != nil {
			return nil, fmt.Errorf("GetAnalytics blocks_over_time scan: %w", err)
		}
		result.BlocksOverTime = append(result.BlocksOverTime, TimeSeriesBucket{
			Hour:  hour.Format(time.RFC3339),
			Count: int(count),
		})
	}

	// Top categories
	catRows, err := r.conn.Query(ctx,
		"SELECT arrayJoin(detector_categories) as category, count() as count "+
			"FROM security_events "+
			"WHERE project_id = @project_id AND verdict IN ('block', 'flag') "+
			"AND timestamp >= @range_start "+
			"GROUP BY category ORDER BY count DESC LIMIT 10",
		baseArgs...,
	)
	if err != nil {
		return nil, fmt.Errorf("GetAnalytics top_categories: %w", err)
	}
	defer func() { _ = catRows.Close() }()
	for catRows.Next() {
		var cat string
		var count uint64
		if err := catRows.Scan(&cat, &count); err != nil {
			return nil, fmt.Errorf("GetAnalytics top_categories scan: %w", err)
		}
		result.TopCategories = append(result.TopCategories, CategoryCount{
			Category: cat, Count: int(count),
		})
	}

	// Shadow report
	var shadowTotal, wouldBlock, wouldFlag uint64
	err = r.conn.QueryRow(ctx,
		"SELECT count() as total, "+
			"countIf(verdict = 'block') as would_block, "+
			"countIf(verdict = 'flag') as would_flag "+
			"FROM security_events "+
			"WHERE project_id = @project_id AND is_shadow = 1 "+
			"AND timestamp >= @range_start",
		baseArgs...,
	).Scan(&shadowTotal, &wouldBlock, &wouldFlag)
	if err != nil {
		return nil, fmt.Errorf("GetAnalytics shadow_report: %w", err)
	}
	result.ShadowReport = ShadowReportStats{
		Total: int(shadowTotal), WouldBlock: int(wouldBlock), WouldFlag: int(wouldFlag),
	}

	// Latency percentiles (last 24h)
	var p50, p95, p99 float64
	err = r.conn.QueryRow(ctx,
		"SELECT quantile(0.5)(latency_ms) as p50, "+
			"quantile(0.95)(latency_ms) as p95, "+
			"quantile(0.99)(latency_ms) as p99 "+
			"FROM security_events "+
			"WHERE project_id = @project_id AND timestamp >= @day_start",
		clickhouse.Named("project_id", projectID),
		clickhouse.Named("day_start", dayStart),
	).Scan(&p50, &p95, &p99)
	if err != nil {
		return nil, fmt.Errorf("GetAnalytics latency: %w", err)
	}
	result.LatencyPercentiles = LatencyStats{
		P50: safeFloat(p50), P95: safeFloat(p95), P99: safeFloat(p99),
	}

	// Top flagged users
	userRows, err := r.conn.Query(ctx,
		"SELECT user_id, count() as count "+
			"FROM security_events "+
			"WHERE project_id = @project_id AND verdict IN ('block', 'flag') "+
			"AND user_id != '' AND timestamp >= @range_start "+
			"GROUP BY user_id ORDER BY count DESC LIMIT 10",
		baseArgs...,
	)
	if err != nil {
		return nil, fmt.Errorf("GetAnalytics top_users: %w", err)
	}
	defer func() { _ = userRows.Close() }()
	for userRows.Next() {
		var uid string
		var count uint64
		if err := userRows.Scan(&uid, &count); err != nil {
			return nil, fmt.Errorf("GetAnalytics top_users scan: %w", err)
		}
		result.TopFlaggedUsers = append(result.TopFlaggedUsers, UserCount{
			UserID: uid, Count: int(count),
		})
	}

	// Ensure slices are non-nil for JSON serialization
	if result.BlocksOverTime == nil {
		result.BlocksOverTime = []TimeSeriesBucket{}
	}
	if result.TopCategories == nil {
		result.TopCategories = []CategoryCount{}
	}
	if result.TopFlaggedUsers == nil {
		result.TopFlaggedUsers = []UserCount{}
	}

	return result, nil
}

// safeFloat replaces NaN/Inf with 0.0.
// ClickHouse returns NaN for quantile() on empty result sets.
func safeFloat(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0.0
	}
	return f
}
