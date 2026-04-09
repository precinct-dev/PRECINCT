FROM golang:1.26.2-alpine@sha256:c2a1f7b2095d046ae14b286b18413a05bb82c9bca9b25fe7ff5efef0f0826166 AS build
WORKDIR /src

# Copy SDK dependency first (cache layer)
COPY sdk/go/ /sdk/go/

# Copy demo source
COPY examples/go/ ./
ARG TARGETARCH
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w" -trimpath -o /demo .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1
COPY --from=build /demo /demo
ENTRYPOINT ["/demo"]
