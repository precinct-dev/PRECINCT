FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /out/content-scanner .

FROM alpine:3.21
RUN adduser -D -u 10001 app
USER app
COPY --from=build /out/content-scanner /usr/local/bin/content-scanner
EXPOSE 8085
ENTRYPOINT ["/usr/local/bin/content-scanner"]
