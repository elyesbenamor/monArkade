FROM golang:1.19-alpine as builder

WORKDIR /app

COPY . .

RUN go build -o arkade .

FROM alpine:latest

RUN apk add --no-cache kubectl helm

COPY --from=builder /app/arkade /usr/local/bin/arkade

ENTRYPOINT ["arkade"]
