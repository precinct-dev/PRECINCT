FROM golang:1.23-alpine AS build

WORKDIR /src
COPY . .
RUN go build -o /out/mock-guard .

FROM alpine:3.20
RUN adduser -D -u 10001 app
USER app
COPY --from=build /out/mock-guard /usr/local/bin/mock-guard
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mock-guard"]

