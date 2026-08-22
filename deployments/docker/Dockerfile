FROM golang:1.25-alpine AS builder

# Install build dependencies for CGO (required by go-sqlite3/modernc.org/sqlite)
RUN apk add --no-cache gcc musl-dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Build with CGO enabled for SQLite
RUN CGO_ENABLED=1 GOOS=linux go build -trimpath -ldflags="-s -w -extldflags '-static'" -o /r3trive ./cmd/r3trive

# Runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 r3trive

COPY --from=builder /r3trive /usr/local/bin/r3trive

# Create default directories and set permissions
RUN mkdir -p /var/lib/r3trive /etc/r3trive && \
    chown -R r3trive:r3trive /var/lib/r3trive /etc/r3trive

USER r3trive
ENTRYPOINT ["/usr/local/bin/r3trive"]
CMD ["serve"]
