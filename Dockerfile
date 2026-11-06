FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
RUN CGO_ENABLED=0 go build -trimpath -o /out/higo ./cmd/api

FROM alpine:3.23
RUN apk add --no-cache ca-certificates
COPY --from=build /out/higo /usr/local/bin/higo
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/higo"]
