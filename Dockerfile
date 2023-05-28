FROM alpine:3 AS builder

RUN apk --no-cache update \
 && apk --no-cache upgrade \
 && apk --no-cache add ca-certificates go

WORKDIR /usr/src/ultra

COPY go.mod ./
COPY go.sum ./
COPY cmd ./cmd
COPY internal ./internal
COPY www ./www

RUN go install github.com/kevinburke/go-bindata/v4/...@latest \
 && find /root -name '*go-bindata*' -print \
 && $HOME/go/bin/go-bindata -o cmd/ultra/croesus.go -prefix www www/...

RUN go test -race ./... \
 && cd cmd/ultra \
 && CGO_ENABLED=0 go build -ldflags '-extldflags "-static"' -o ultra


FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/src/ultra/cmd/ultra/ultra /ultra

ENTRYPOINT ["/ultra"]
