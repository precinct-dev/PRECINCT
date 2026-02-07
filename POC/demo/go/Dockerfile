FROM golang:1.24-alpine AS build
WORKDIR /src

# Copy SDK dependency first (cache layer)
COPY sdk/go/ /sdk/go/

# Copy demo source
COPY demo/go/ ./
RUN go mod tidy && go build -o /demo .

FROM alpine:3.21
COPY --from=build /demo /demo
ENTRYPOINT ["/demo"]
