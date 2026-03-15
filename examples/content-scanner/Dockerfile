FROM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS build
WORKDIR /src
COPY . .
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w" -trimpath -o /out/content-scanner .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1
COPY --from=build /out/content-scanner /usr/local/bin/content-scanner
EXPOSE 8085
ENTRYPOINT ["/usr/local/bin/content-scanner"]
