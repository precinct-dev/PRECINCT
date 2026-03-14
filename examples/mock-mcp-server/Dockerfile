FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go build -o /mock-mcp-server .

FROM alpine:3.21@sha256:c3f8e73fdb79deaebaa2037150150191b9dcbfba68b4a46d70103204c53f4709
# Run as non-root in the runtime image (RFA-545e.3).
RUN adduser -D -u 10001 app
USER app
COPY --from=build /mock-mcp-server /mock-mcp-server
EXPOSE 8082
ENTRYPOINT ["/mock-mcp-server"]
