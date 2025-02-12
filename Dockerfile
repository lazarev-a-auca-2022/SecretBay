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
RUN apk --no-cache add ca-certificates

# Ensure /root/.ssh exists and create a blank known_hosts file
RUN mkdir -p /root/.ssh && touch /root/.ssh/known_hosts

WORKDIR /app
COPY --from=builder /app/vpn-setup-server .
COPY static/ /app/static/
EXPOSE 9999 443
CMD ["./vpn-setup-server"]