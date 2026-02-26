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

// ClickHouseWriter writes tool check events to ClickHouse asynchronously.
// Write() is non-blocking — events are buffered and batch-inserted in a background goroutine.
type ClickHouseWriter struct {
	conn    driver.Conn
	buffer  chan *ToolCheckEvent
	done    chan struct{}
	flushed chan struct{}
	logger  *zap.Logger
}

// NewClickHouseWriter creates a ClickHouseWriter and starts the background flush loop.
func NewClickHouseWriter(dsn string, logger *zap.Logger) (*ClickHouseWriter, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}

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
		buffer:  make(chan *ToolCheckEvent, bufferSize),
		done:    make(chan struct{}),
		flushed: make(chan struct{}),
		logger:  logger,
	}

	go w.flushLoop()
	return w, nil
}

// Write queues a tool check event for async insertion.
// Non-blocking: drops the event if the buffer is full.
func (w *ClickHouseWriter) Write(event *ToolCheckEvent) {
	select {
	case w.buffer <- event:
	default:
		w.logger.Warn("clickhouse buffer full, dropping event",
			zap.String("request_id", event.RequestID),
		)
	}
}

// Close signals the flush loop to drain remaining events.
func (w *ClickHouseWriter) Close() {
	close(w.done)
	<-w.flushed
}

func (w *ClickHouseWriter) flushLoop() {
	defer close(w.flushed)

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	batch := make([]*ToolCheckEvent, 0, flushBatch)

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

func (w *ClickHouseWriter) flush(events []*ToolCheckEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	batch, err := w.conn.PrepareBatch(ctx, `
		INSERT INTO tool_check_events (
			request_id, project_id, timestamp, tool_name, arguments_json,
			verdict, reason,
			eval_categories, eval_triggered, eval_confidences, eval_details,
			user_id, session_id, tenant_id, client_trace_id,
			workflow_type, user_confirmed, trace_length,
			metadata, latency_ms, source
		)
	`)
	if err != nil {
		w.logger.Error("clickhouse prepare batch failed", zap.Error(err))
		return
	}

	for _, e := range events {
		triggeredUint8 := make([]uint8, len(e.EvalTriggered))
		for i, t := range e.EvalTriggered {
			if t {
				triggeredUint8[i] = 1
			}
		}

		var confirmedUint8 uint8
		if e.UserConfirmed {
			confirmedUint8 = 1
		}

		if err := batch.Append(
			e.RequestID,
			e.ProjectID,
			e.Timestamp,
			e.ToolName,
			e.ArgumentsJSON,
			e.Verdict,
			e.Reason,
			e.EvalCategories,
			triggeredUint8,
			e.EvalConfidences,
			e.EvalDetails,
			e.UserID,
			e.SessionID,
			e.TenantID,
			e.ClientTraceID,
			e.WorkflowType,
			confirmedUint8,
			e.TraceLength,
			e.Metadata,
			e.LatencyMs,
			e.Source,
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
type LogWriter struct {
	logger *zap.Logger
}

// NewLogWriter creates a LogWriter that outputs events to the given logger.
func NewLogWriter(logger *zap.Logger) *LogWriter {
	return &LogWriter{logger: logger}
}

func (w *LogWriter) Write(event *ToolCheckEvent) {
	w.logger.Info("tool_check_event",
		zap.String("request_id", event.RequestID),
		zap.String("project_id", event.ProjectID),
		zap.String("tool_name", event.ToolName),
		zap.String("verdict", event.Verdict),
		zap.String("reason", event.Reason),
		zap.Strings("eval_categories", event.EvalCategories),
		zap.Float32("latency_ms", event.LatencyMs),
		zap.String("user_id", event.UserID),
		zap.String("workflow_type", event.WorkflowType),
	)
}

func (w *LogWriter) Close() {}
