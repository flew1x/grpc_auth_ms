FROM golang:1.22.3-alpine AS builder

WORKDIR /app

COPY . .

RUN go build -o main ./cmd/app/main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/main .

CMD ["./main"]