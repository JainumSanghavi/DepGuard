FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOFLAGS=-mod=mod go build -o depguard ./cmd/depguard

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/depguard /usr/local/bin/depguard
ENTRYPOINT ["depguard"]
