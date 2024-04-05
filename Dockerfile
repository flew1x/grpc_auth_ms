FROM golang:1.22-alpine

WORKDIR /app

COPY . .

RUN go build ./cmd/app/main.go

CMD ["./main"]