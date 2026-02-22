# === Builder ===
# Match go.mod version (1.25). Alpine for smaller builder image.
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Copy go.mod/go.sum first — this layer is cached until dependencies change.
COPY guard/go.mod guard/go.sum ./guard/
WORKDIR /src/guard
RUN go mod download

# Copy source code (guard + proto for generated stubs).
WORKDIR /src
COPY guard/ ./guard/
COPY proto/ ./proto/

# Build a static binary (no cgo, no libc dependency).
# -s strips symbol table, -w strips DWARF — shrinks binary ~30%.
WORKDIR /src/guard
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /guard-server ./cmd/guard-server/

# === Runtime ===
# Distroless: no shell, no package manager, no libc — just the binary.
# "nonroot" variant runs as uid 65534 (not root).
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /guard-server /guard-server

EXPOSE 50051

ENTRYPOINT ["/guard-server"]
