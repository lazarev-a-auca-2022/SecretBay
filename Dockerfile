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
WORKDIR /root/
COPY --from=builder /app/vpn-setup-server .
EXPOSE 8081
STOPSIGNAL SIGTERM
CMD ["./vpn-setup-server"]