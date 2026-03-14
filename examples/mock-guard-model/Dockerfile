FROM golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f AS build

WORKDIR /src
COPY . .
RUN go build -o /out/mock-guard .

FROM alpine:3.20@sha256:a4f4213abb84c497377b8544c81b3564f313746700372ec4fe84653e4fb03805
RUN adduser -D -u 10001 app
USER app
COPY --from=build /out/mock-guard /usr/local/bin/mock-guard
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mock-guard"]
