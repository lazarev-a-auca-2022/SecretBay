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

# Build with output directory explicitly set
RUN mkdir -p /build/bin && \
    go build -v -o /build/bin/vpn-setup-server ./cmd/server && \
    chmod +x /build/bin/vpn-setup-server

FROM alpine:latest
RUN apk --no-cache add ca-certificates openssh-client curl

# Create non-root user with specific UID/GID
RUN addgroup -g 1000 appgroup && \
    adduser -D -u 1000 -G appgroup -s /sbin/nologin appuser

WORKDIR /app

# Copy binary first and set permissions
COPY --from=builder --chown=appuser:appgroup /build/bin/vpn-setup-server /app/
RUN chmod 755 /app/vpn-setup-server

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

WORKDIR /app
CMD ["/app/vpn-setup-server"]