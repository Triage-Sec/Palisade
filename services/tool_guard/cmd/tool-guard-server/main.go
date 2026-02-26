package main

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	toolguardv1 "github.com/triage-ai/palisade/services/tool_guard/gen/tool_guard/v1"
	"github.com/triage-ai/palisade/services/tool_guard/internal/auth"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine"
	"github.com/triage-ai/palisade/services/tool_guard/internal/engine/evaluators"
	"github.com/triage-ai/palisade/services/tool_guard/internal/registry"
	"github.com/triage-ai/palisade/services/tool_guard/internal/server"
	"github.com/triage-ai/palisade/services/tool_guard/internal/storage"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Logger
	logger := mustBuildLogger(envOrDefault("TOOL_GUARD_LOG_LEVEL", "info"))
	defer logger.Sync() //nolint:errcheck // best-effort flush

	// Config from env
	port := envOrDefault("TOOL_GUARD_PORT", "50053")
	evalTimeoutMs := envOrDefaultInt("TOOL_GUARD_EVAL_TIMEOUT_MS", 25)
	unsafeThreshold := envOrDefaultFloat("TOOL_GUARD_UNSAFE_THRESHOLD", 0.8)
	clickhouseDSN := os.Getenv("CLICKHOUSE_DSN")
	postgresDSN := os.Getenv("POSTGRES_DSN")
	authCacheTTL := envOrDefaultInt("TOOL_GUARD_AUTH_CACHE_TTL_S", 30)
	toolCacheTTL := envOrDefaultInt("TOOL_GUARD_TOOL_CACHE_TTL_S", 60)

	evalTimeout := time.Duration(evalTimeoutMs) * time.Millisecond

	logger.Info("starting tool guard server",
		zap.String("port", port),
		zap.Int("eval_timeout_ms", evalTimeoutMs),
		zap.Float32("unsafe_threshold", unsafeThreshold),
	)

	// Evaluators
	evals := []engine.Evaluator{
		evaluators.NewRiskTierEvaluator(),
		evaluators.NewPreconditionEvaluator(),
		evaluators.NewArgumentValidationEvaluator(),
		evaluators.NewContextualRulesEvaluator(),
		evaluators.NewInformationFlowEvaluator(),
	}

	eng := engine.NewToolGuardEngine(evals, evalTimeout, logger)

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

	// Auth — Postgres if DSN provided, otherwise static (backward compatible)
	var authenticator auth.Authenticator
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
		authenticator = auth.NewPostgresAuthenticator(auth.PostgresAuthConfig{
			DB:       db,
			CacheTTL: time.Duration(authCacheTTL) * time.Second,
			FailOpen: true,
			Logger:   logger,
		})
		logger.Info("postgres authenticator connected")
	} else {
		authenticator = auth.NewStaticAuthenticator()
		logger.Info("using static authenticator (no POSTGRES_DSN)")
	}

	// Tool registry — Postgres if DSN provided, otherwise nil (unregistered tool path)
	var toolRegistry registry.ToolRegistry
	if postgresDSN != "" {
		db, err := sql.Open("pgx", postgresDSN)
		if err != nil {
			logger.Fatal("failed to open postgres for registry", zap.Error(err))
		}
		defer func() { _ = db.Close() }()
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(5 * time.Minute)
		toolRegistry = registry.NewPostgresToolRegistry(registry.PostgresToolRegistryConfig{
			DB:       db,
			CacheTTL: time.Duration(toolCacheTTL) * time.Second,
			Logger:   logger,
		})
		logger.Info("postgres tool registry connected")
	} else {
		logger.Info("no POSTGRES_DSN set, all tools treated as unregistered")
	}

	// Aggregator config
	aggCfg := engine.AggregatorConfig{
		UnsafeThreshold: unsafeThreshold,
	}

	// gRPC server
	grpcServer := grpc.NewServer(
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     5 * time.Minute,
			MaxConnectionAge:      30 * time.Minute,
			MaxConnectionAgeGrace: 10 * time.Second,
			Time:                  30 * time.Second,
			Timeout:               5 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.MaxRecvMsgSize(4*1024*1024),
		grpc.MaxSendMsgSize(4*1024*1024),
	)

	// Register tool guard service
	toolGuardServer := server.NewToolGuardServer(eng, authenticator, toolRegistry, writer, aggCfg, logger)
	toolguardv1.RegisterToolGuardServiceServer(grpcServer, toolGuardServer)

	// Register health service for ECS health checks
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("triage.tool_guard.v1.ToolGuardService", healthpb.HealthCheckResponse_SERVING)

	// Enable reflection for debugging with grpcurl
	reflection.Register(grpcServer)

	// Listen
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		logger.Fatal("failed to listen", zap.String("port", port), zap.Error(err))
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("received signal, shutting down", zap.String("signal", sig.String()))
		healthServer.SetServingStatus("triage.tool_guard.v1.ToolGuardService", healthpb.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
	}()

	logger.Info("tool guard server listening", zap.String("addr", lis.Addr().String()))
	if err := grpcServer.Serve(lis); err != nil {
		logger.Fatal("grpc server failed", zap.Error(err))
	}
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
