PROTO_DIR := ../../proto
GEN_DIR := src/prompt_guard/gen

.PHONY: proto run test lint docker

## — Proto —

proto:
	python -m grpc_tools.protoc \
		-I $(PROTO_DIR) \
		--python_out=$(GEN_DIR) \
		--grpc_python_out=$(GEN_DIR) \
		--pyi_out=$(GEN_DIR) \
		$(PROTO_DIR)/prompt_guard/v1/prompt_guard.proto

## — Run —

run:
	python -m prompt_guard.server

## — Test —

test:
	python -m pytest tests/ -v

## — Lint —

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff check --fix src/ tests/
	ruff format src/ tests/

## — Docker —

docker:
	docker build -f deploy/Dockerfile -t palisade-prompt-guard ../..
