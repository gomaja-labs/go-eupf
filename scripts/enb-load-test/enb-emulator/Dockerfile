FROM golang:1.27.4-bookworm

RUN groupadd -g 10001 build \
    && useradd -m -u 10001 -g build build \
    && mkdir /app \
    && chown build:build /app /go
USER build
WORKDIR /app

COPY --chown=build:build . .

RUN go mod download

RUN CGO_ENABLED=0 go build -v -o /app/app main.go

CMD ["/app/app"]
