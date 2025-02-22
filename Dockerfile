FROM golang:1.20-alpine AS builder
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /build

# Copy only necessary files first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Debug: List contents
RUN ls -la && \
    ls -la cmd/server

# Build with verbose output and verify
RUN go build -v -o vpn-setup-server ./cmd/server && \
    chmod +x vpn-setup-server && \
    ls -l vpn-setup-server && \
    pwd && \
    ./vpn-setup-server -version || true

FROM alpine:latest
RUN apk --no-cache add ca-certificates openssh-client curl

# Create non-root user with specific UID/GID
RUN addgroup -g 1000 appgroup && \
    adduser -D -u 1000 -G appgroup -s /sbin/nologin appuser

WORKDIR /app

# Copy binary first and set permissions
COPY --from=builder --chown=appuser:appgroup /build/vpn-setup-server .
RUN chmod 755 /app/vpn-setup-server && \
    ls -l /app/vpn-setup-server

# Create directories with proper permissions
RUN mkdir -p /app/static /app/certs /app/logs /app/metrics && \
    chown -R appuser:appgroup /app && \
    chmod -R 755 /app && \
    mkdir -p /home/appuser/.ssh && \
    chown -R appuser:appgroup /home/appuser/.ssh && \
    chmod 700 /home/appuser/.ssh && \
    touch /home/appuser/.ssh/known_hosts && \
    chown appuser:appgroup /home/appuser/.ssh/known_hosts

# Copy static files
COPY --chown=appuser:appgroup static/ /app/static/

# Switch to non-root user
USER appuser:appgroup

EXPOSE 9999 443

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -k https://localhost:9999/health || exit 1

CMD ["./vpn-setup-server"]