# Use official Golang image as build stage
FROM golang:1.20-alpine AS builder

# Set environment variables
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Set work directory
WORKDIR /app

# Copy go.mod and go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o vpn-setup-server ./cmd/server

# Use a minimal image for the final stage
FROM alpine:latest

# Install necessary packages
RUN apk --no-cache add ca-certificates

# Set work directory
WORKDIR /root/

# Copy the binary from the builder
COPY --from=builder /app/vpn-setup-server .

# Expose port
EXPOSE 8080

# Command to run the executable
CMD ["./vpn-setup-server"]