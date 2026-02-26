# Load .env from repo root if it exists
ifneq (,$(wildcard ../../.env))
include ../../.env
export
endif

BINARY_NAME := tool-guard-server
BUILD_DIR := bin
PROTO_DIR := ../../proto
GEN_DIR := gen

.PHONY: proto build test bench lint docker run

## — Build & Run —

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/tool-guard-server/

run: build
	CLICKHOUSE_DSN="$(CLICKHOUSE_DSN)" ./$(BUILD_DIR)/$(BINARY_NAME)

## — Proto —

proto:
	protoc \
		--go_out=$(GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=paths=source_relative \
		-I $(PROTO_DIR) \
		$(PROTO_DIR)/tool_guard/v1/tool_guard.proto

## — Test —

test:
	go test ./... -v

bench:
	go test -bench=. -benchmem ./...

lint:
	golangci-lint run ./...

## — Docker —

docker:
	docker build -f deploy/Dockerfile -t palisade-tool-guard ../..
