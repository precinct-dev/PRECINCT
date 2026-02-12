FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go build -o /mock-mcp-server .

FROM alpine:3.21
# Run as non-root in the runtime image (RFA-545e.3).
RUN adduser -D -u 10001 app
USER app
COPY --from=build /mock-mcp-server /mock-mcp-server
EXPOSE 8082
ENTRYPOINT ["/mock-mcp-server"]
