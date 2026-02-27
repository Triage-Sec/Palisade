# Load .env from repo root if it exists
ifneq (,$(wildcard ../.env))
include ../.env
export
endif

BINARY_NAME := guard-server
BUILD_DIR := bin
PROTO_DIR := ../proto
GEN_DIR := gen

.PHONY: proto-prompt-guard build test bench lint docker run migrate-up migrate-down migrate-create

## — Build & Run —

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/guard-server/

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

## — Proto —

proto-prompt-guard:
	protoc \
		--go_out=$(GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=paths=source_relative \
		-I $(PROTO_DIR) \
		$(PROTO_DIR)/prompt_guard/v1/prompt_guard.proto

## — Test —

test:
	go test ./... -v

bench:
	go test -bench=. -benchmem ./...

lint:
	golangci-lint run ./...

## — Migrations (golang-migrate) —

migrate-up:
	migrate -path migrations -database "$(CLICKHOUSE_MIGRATE_DSN)" up

migrate-down:
	migrate -path migrations -database "$(CLICKHOUSE_MIGRATE_DSN)" down

migrate-down-one:
	migrate -path migrations -database "$(CLICKHOUSE_MIGRATE_DSN)" down 1

migrate-version:
	migrate -path migrations -database "$(CLICKHOUSE_MIGRATE_DSN)" version

migrate-create:
	migrate create -ext sql -dir migrations -seq $(name)

## — Docker —

docker:
	docker build -f deploy/Dockerfile -t palisade-guard ..
