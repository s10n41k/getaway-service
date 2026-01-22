FROM golang:1.23 AS builder

WORKDIR /app
COPY . /app
RUN go build -o /app/gateway ./app/cmd

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y libc6

COPY --from=builder /app/gateway /app/gateway

WORKDIR /app
CMD ["/app/gateway"]
