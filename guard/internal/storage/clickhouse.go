package storage

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
)

const (
	bufferSize    = 10_000
	flushInterval = 100 * time.Millisecond
	flushBatch    = 1000
	drainTimeout  = 2 * time.Second
)

// ClickHouseWriter writes security events to ClickHouse asynchronously.
// Write() is non-blocking — events are buffered and batch-inserted in a background goroutine.
type ClickHouseWriter struct {
	conn    driver.Conn
	buffer  chan *SecurityEvent
	done    chan struct{}
	flushed chan struct{} // closed by flushLoop when it returns
	logger  *zap.Logger
}

// NewClickHouseWriter creates a ClickHouseWriter and starts the background flush loop.
func NewClickHouseWriter(dsn string, logger *zap.Logger) (*ClickHouseWriter, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}

	// Ensure TLS is enabled for secure connections (e.g. ClickHouse Cloud on port 9440).
	// ParseDSN sets this when ?secure=true is in the DSN, but we enforce it here
	// as a safety net to match ClickHouse Cloud's official Go connection example.
	if opts.TLS == nil {
		opts.TLS = &tls.Config{}
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, err
	}

	if err := conn.Ping(context.Background()); err != nil {
		return nil, err
	}

	w := &ClickHouseWriter{
		conn:    conn,
		buffer:  make(chan *SecurityEvent, bufferSize),
		done:    make(chan struct{}),
		flushed: make(chan struct{}),
		logger:  logger,
	}

	go w.flushLoop()
	return w, nil
}

// Write queues a security event for async insertion.
// Non-blocking: drops the event if the buffer is full.
func (w *ClickHouseWriter) Write(event *SecurityEvent) {
	select {
	case w.buffer <- event:
	default:
		w.logger.Warn("clickhouse buffer full, dropping event",
			zap.String("request_id", event.RequestID),
		)
	}
}

// Close signals the flush loop to drain remaining events, waits for it to
// finish (up to drainTimeout), and then returns. Safe to call once.
func (w *ClickHouseWriter) Close() {
	close(w.done)
	<-w.flushed
}

func (w *ClickHouseWriter) flushLoop() {
	defer close(w.flushed)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]*SecurityEvent, 0, flushBatch)

	for {
		select {
		case event := <-w.buffer:
			batch = append(batch, event)
			if len(batch) >= flushBatch {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				w.flush(batch)
				batch = batch[:0]
			}
		case <-w.done:
			// Drain remaining events from buffer
			drainCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
			defer cancel()
		drainLoop:
			for {
				select {
				case event := <-w.buffer:
					batch = append(batch, event)
				case <-drainCtx.Done():
					break drainLoop
				default:
					break drainLoop
				}
			}
			if len(batch) > 0 {
				w.flush(batch)
			}
			return
		}
	}
}

func (w *ClickHouseWriter) flush(events []*SecurityEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	batch, err := w.conn.PrepareBatch(ctx, `
		INSERT INTO security_events (
			request_id, project_id, timestamp, action,
			payload_preview, payload_hash, payload_size,
			verdict, is_shadow, reason,
			detector_names, detector_triggered, detector_confidences, detector_categories, detector_details,
			user_id, session_id, tenant_id, client_trace_id,
			tool_name, tool_arguments, metadata,
			latency_ms, source, sdk_language, sdk_version
		)
	`)
	if err != nil {
		w.logger.Error("clickhouse prepare batch failed", zap.Error(err))
		return
	}

	for _, e := range events {
		// Convert []bool to []uint8 for ClickHouse
		triggeredUint8 := make([]uint8, len(e.DetectorTriggered))
		for i, t := range e.DetectorTriggered {
			if t {
				triggeredUint8[i] = 1
			}
		}

		var isShadowUint8 uint8
		if e.IsShadow {
			isShadowUint8 = 1
		}

		if err := batch.Append(
			e.RequestID,
			e.ProjectID,
			e.Timestamp,
			e.Action,
			e.PayloadPreview,
			e.PayloadHash,
			e.PayloadSize,
			e.Verdict,
			isShadowUint8,
			e.Reason,
			e.DetectorNames,
			triggeredUint8,
			e.DetectorConfidences,
			e.DetectorCategories,
			e.DetectorDetails,
			e.UserID,
			e.SessionID,
			e.TenantID,
			e.ClientTraceID,
			e.ToolName,
			e.ToolArguments,
			e.Metadata,
			e.LatencyMs,
			e.Source,
			e.SDKLanguage,
			e.SDKVersion,
		); err != nil {
			w.logger.Error("clickhouse append event failed",
				zap.String("request_id", e.RequestID),
				zap.Error(err),
			)
		}
	}

	if err := batch.Send(); err != nil {
		w.logger.Error("clickhouse batch send failed",
			zap.Int("batch_size", len(events)),
			zap.Error(err),
		)
	}
}

// LogWriter is a fallback EventWriter for local development.
// It logs events as structured JSON to stdout via zap.
type LogWriter struct {
	logger *zap.Logger
}

// NewLogWriter creates a LogWriter that outputs events to the given logger.
func NewLogWriter(logger *zap.Logger) *LogWriter {
	return &LogWriter{logger: logger}
}

func (w *LogWriter) Write(event *SecurityEvent) {
	w.logger.Info("security_event",
		zap.String("request_id", event.RequestID),
		zap.String("project_id", event.ProjectID),
		zap.String("action", event.Action),
		zap.String("verdict", event.Verdict),
		zap.Bool("is_shadow", event.IsShadow),
		zap.String("reason", event.Reason),
		zap.Strings("detector_names", event.DetectorNames),
		zap.Float32("latency_ms", event.LatencyMs),
		zap.String("user_id", event.UserID),
		zap.String("payload_preview", event.PayloadPreview),
	)
}

func (w *LogWriter) Close() {}
