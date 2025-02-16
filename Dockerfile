FROM golang:1.20-alpine AS builder
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o vpn-setup-server ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates openssh-client curl

# Create non-root user with specific UID/GID
RUN addgroup -g 1000 appgroup && \
    adduser -D -u 1000 -G appgroup -s /sbin/nologin appuser

# Ensure required directories exist with proper permissions
RUN mkdir -p /app/static /app/certs /app/logs /app/metrics && \
    chown -R appuser:appgroup /app && \
    mkdir -p /home/appuser/.ssh && \
    touch /home/appuser/.ssh/known_hosts && \
    chown -R appuser:appgroup /home/appuser/.ssh && \
    chmod 700 /home/appuser/.ssh && \
    chmod -R 755 /app/static && \
    chown -R appuser:appgroup /app/certs && \
    chmod 755 /app/certs && \
    chmod 755 /app/logs && \
    chmod 755 /app/metrics

WORKDIR /app
COPY --from=builder /app/vpn-setup-server .
COPY static/ /app/static/

# Set final permissions
RUN chown -R appuser:appgroup /app && \
    chmod 755 vpn-setup-server

# Switch to non-root user
USER appuser:appgroup

EXPOSE 9999 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -k https://localhost:9999/health || exit 1

CMD ["./vpn-setup-server"]