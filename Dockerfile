FROM golang:1.20-alpine AS builder
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build
COPY . .

# Verify source files are copied
RUN ls -la && \
    ls -la cmd/server

# Build with verbose output
RUN go build -v -o vpn-setup-server ./cmd/server && \
    # Verify binary exists and is executable
    ls -l vpn-setup-server && \
    ./vpn-setup-server -version || true

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

# Copy binary and verify
COPY --from=builder /build/vpn-setup-server /app/
RUN ls -l /app/vpn-setup-server && \
    chown appuser:appgroup /app/vpn-setup-server && \
    chmod 755 /app/vpn-setup-server

# Copy static files
COPY static/ /app/static/

# Set final permissions
RUN chown -R appuser:appgroup /app && \
    chmod -R 755 /app/static

# Switch to non-root user
USER appuser:appgroup

EXPOSE 9999 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -k https://localhost:9999/health || exit 1

CMD ["/app/vpn-setup-server"]