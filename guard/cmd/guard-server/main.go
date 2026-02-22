package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	guardv1 "github.com/triage-ai/palisade/gen/guard/v1"
	"github.com/triage-ai/palisade/internal/auth"
	"github.com/triage-ai/palisade/internal/engine"
	"github.com/triage-ai/palisade/internal/engine/detectors"
	"github.com/triage-ai/palisade/internal/server"
	"github.com/triage-ai/palisade/internal/storage"
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
	logger := mustBuildLogger(envOrDefault("GUARD_LOG_LEVEL", "info"))
	defer logger.Sync() //nolint:errcheck // best-effort flush

	// Config from env
	port := envOrDefault("GUARD_PORT", "50051")
	detectorTimeoutMs := envOrDefaultInt("GUARD_DETECTOR_TIMEOUT_MS", 25)
	blockThreshold := envOrDefaultFloat("GUARD_BLOCK_THRESHOLD", 0.8)
	flagThreshold := envOrDefaultFloat("GUARD_FLAG_THRESHOLD", 0.0)
	clickhouseDSN := os.Getenv("CLICKHOUSE_DSN")

	detectorTimeout := time.Duration(detectorTimeoutMs) * time.Millisecond

	logger.Info("starting guard server",
		zap.String("port", port),
		zap.Int("detector_timeout_ms", detectorTimeoutMs),
		zap.Float32("block_threshold", blockThreshold),
		zap.Float32("flag_threshold", flagThreshold),
	)

	// Engine — all Phase 1 detectors wired up here to avoid import cycle
	dets := []engine.Detector{
		detectors.NewPromptInjectionDetector(),
		detectors.NewJailbreakDetector(),
		detectors.NewPIIDetector(),
		detectors.NewContentModDetector(),
		detectors.NewToolAbuseDetector(),
	}
	eng := engine.NewSentryEngine(dets, detectorTimeout, logger)

	// Auth — static authenticator (Phase 1)
	authenticator := auth.NewStaticAuthenticator()

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

	// Register guard service
	guardServer := server.NewGuardServer(eng, authenticator, writer, aggCfg, logger)
	guardv1.RegisterGuardServiceServer(grpcServer, guardServer)

	// Register health service for ECS health checks
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("triage.guard.v1.GuardService", healthpb.HealthCheckResponse_SERVING)

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
		healthServer.SetServingStatus("triage.guard.v1.GuardService", healthpb.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
	}()

	logger.Info("guard server listening", zap.String("addr", lis.Addr().String()))
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
