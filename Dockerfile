FROM alpine:3 AS builder

RUN apk --no-cache update \
 && apk --no-cache upgrade \
 && apk --no-cache add ca-certificates go

WORKDIR /usr/src/ultra

COPY go.mod ./
COPY go.sum ./
COPY cmd ./cmd
COPY internal ./internal

RUN go test -race ./... \
 && cd cmd/ultra \
 && CGO_ENABLED=0 go build -ldflags '-extldflags "-static"' -o ultra


FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/src/ultra/cmd/ultra/ultra /ultra

ENTRYPOINT ["/ultra"]
