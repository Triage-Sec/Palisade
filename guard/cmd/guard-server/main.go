package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // Register pgx as database/sql driver
	"github.com/triage-ai/palisade/internal/api"
	"github.com/triage-ai/palisade/internal/chread"
	"github.com/triage-ai/palisade/internal/engine"
	"github.com/triage-ai/palisade/internal/engine/detectors"
	"github.com/triage-ai/palisade/internal/storage"
	"github.com/triage-ai/palisade/internal/store"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	// Logger
	logger := mustBuildLogger(envOrDefault("GUARD_LOG_LEVEL", "info"))
	defer logger.Sync() //nolint:errcheck // best-effort flush

	// Config from env
	httpPort := envOrDefault("GUARD_HTTP_PORT", "8080")
	detectorTimeoutMs := envOrDefaultInt("GUARD_DETECTOR_TIMEOUT_MS", 100)
	blockThreshold := envOrDefaultFloat("GUARD_BLOCK_THRESHOLD", 0.8)
	flagThreshold := envOrDefaultFloat("GUARD_FLAG_THRESHOLD", 0.0)
	clickhouseDSN := os.Getenv("CLICKHOUSE_DSN")
	postgresDSN := os.Getenv("POSTGRES_DSN")
	cacheTTL := envOrDefaultInt("GUARD_AUTH_CACHE_TTL_S", 30)

	detectorTimeout := time.Duration(detectorTimeoutMs) * time.Millisecond

	logger.Info("starting guard server",
		zap.String("http_port", httpPort),
		zap.Int("detector_timeout_ms", detectorTimeoutMs),
		zap.Float32("block_threshold", blockThreshold),
		zap.Float32("flag_threshold", flagThreshold),
	)

	// Engine — detectors wired up here to avoid import cycle
	dets := []engine.Detector{
		detectors.NewPIIDetector(),
		detectors.NewContentModDetector(),
		detectors.NewToolAbuseDetector(),
	}

	// ML detector — prompt injection + jailbreak classification via prompt_guard gRPC service.
	// Replaces the old regex-based prompt_injection and jailbreak detectors.
	if endpoint := os.Getenv("PROMPT_GUARD_ENDPOINT"); endpoint != "" {
		mlDet, err := detectors.NewMLPromptInjectionDetector(endpoint, logger)
		if err != nil {
			logger.Error("failed to create ml prompt injection detector, skipping",
				zap.String("endpoint", endpoint),
				zap.Error(err),
			)
		} else {
			dets = append(dets, mlDet)
			logger.Info("ml prompt injection detector enabled",
				zap.String("endpoint", endpoint),
			)
		}
	}

	eng := engine.NewSentryEngine(dets, detectorTimeout, logger)

	// Storage — ClickHouse or LogWriter fallback
	var writer storage.EventWriter
	if clickhouseDSN != "" {
		chWriter, err := storage.NewClickHouseWriter(clickhouseDSN, logger)
		if err != nil {
			logger.Warn("clickhouse connection failed, falling back to log writer",
				zap.Error(err),
			)
			writer = storage.NewLogWriter(logger)
		} else {
			writer = chWriter
			logger.Info("clickhouse writer connected")
		}
	} else {
		writer = storage.NewLogWriter(logger)
		logger.Info("no CLICKHOUSE_DSN set, using log writer")
	}
	defer writer.Close()

	// Aggregator config
	aggCfg := engine.AggregatorConfig{
		BlockThreshold: blockThreshold,
		FlagThreshold:  flagThreshold,
	}

	// Postgres pool (required for HTTP API)
	var pgStore *store.Store
	if postgresDSN != "" {
		db, err := sql.Open("pgx", postgresDSN)
		if err != nil {
			logger.Fatal("failed to open postgres", zap.Error(err))
		}
		defer func() { _ = db.Close() }()
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)
		if err := db.PingContext(context.Background()); err != nil {
			logger.Fatal("failed to ping postgres", zap.Error(err))
		}
		pgStore = store.NewStore(db)
		logger.Info("postgres connected")
	} else {
		logger.Info("no POSTGRES_DSN set, HTTP API will not be available")
	}

	// ClickHouse reader (for events/analytics HTTP endpoints)
	var chReader *chread.Reader
	if clickhouseDSN != "" {
		var err error
		chReader, err = chread.NewReader(clickhouseDSN, logger)
		if err != nil {
			logger.Warn("clickhouse reader connection failed", zap.Error(err))
		} else {
			defer func() { _ = chReader.Close() }()
			logger.Info("clickhouse reader connected")
		}
	}

	// HTTP API server (only starts if Postgres is configured)
	var httpServer *http.Server
	if pgStore != nil {
		deps := &api.Dependencies{
			Store:    pgStore,
			Engine:   eng,
			Writer:   writer,
			Reader:   chReader,
			AggCfg:   aggCfg,
			Logger:   logger,
			CacheTTL: time.Duration(cacheTTL) * time.Second,
		}
		httpServer = &http.Server{
			Addr:         ":" + httpPort,
			Handler:      api.NewRouter(deps),
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		go func() {
			logger.Info("http server listening", zap.String("addr", httpServer.Addr))
			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("http server failed", zap.Error(err))
			}
		}()
	} else {
		logger.Fatal("POSTGRES_DSN is required")
	}

	// Block until shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("received signal, shutting down", zap.String("signal", sig.String()))

	// Graceful shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("http server shutdown error", zap.Error(err))
	}

	logger.Info("guard server stopped")
}

func mustBuildLogger(level string) *zap.Logger {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapLevel),
		Development:      false,
		Encoding:         "json",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	logger, err := cfg.Build()
	if err != nil {
		panic(fmt.Sprintf("failed to build logger: %v", err))
	}
	return logger
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envOrDefaultInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultVal
}

func envOrDefaultFloat(key string, defaultVal float32) float32 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 32); err == nil {
			return float32(f)
		}
	}
	return defaultVal
}
