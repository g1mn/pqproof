# Build the API, then run it behind nginx.
FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY . .
ENV GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0
RUN go build -trimpath -o /out/api ./cmd/api

FROM nginx:1.28-bookworm
COPY --from=build /out/api /usr/local/bin/orders-api
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY scripts/start.sh /start.sh
# TLS material (cert.pem, key.pem, ca.pem) is mounted at /etc/orders-edge/tls at run time.
EXPOSE 8443
CMD ["/start.sh"]
