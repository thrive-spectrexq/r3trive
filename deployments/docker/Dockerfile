FROM golang:1.22-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /r3trive ./cmd/r3trive

# Runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 r3trive

COPY --from=builder /r3trive /usr/local/bin/r3trive

USER r3trive
ENTRYPOINT ["/usr/local/bin/r3trive"]
CMD ["monitor"]
