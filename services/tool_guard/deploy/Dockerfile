# === Builder ===
# Match go.mod version (1.25). Alpine for smaller builder image.
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Copy go.mod/go.sum first — this layer is cached until dependencies change.
COPY services/tool_guard/go.mod services/tool_guard/go.sum ./services/tool_guard/
WORKDIR /src/services/tool_guard
RUN go mod download

# Copy source code (tool_guard + proto for generated stubs).
WORKDIR /src
COPY services/tool_guard/ ./services/tool_guard/
COPY proto/ ./proto/

# Build a static binary (no cgo, no libc dependency).
# -s strips symbol table, -w strips DWARF — shrinks binary ~30%.
WORKDIR /src/services/tool_guard
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /tool-guard-server ./cmd/tool-guard-server/

# === Runtime ===
# Distroless: no shell, no package manager, no libc — just the binary.
# "nonroot" variant runs as uid 65534 (not root).
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /tool-guard-server /tool-guard-server

EXPOSE 50053

ENTRYPOINT ["/tool-guard-server"]
