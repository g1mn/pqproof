# Build the API, then run it behind nginx.
FROM golang:1.27-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
WORKDIR /src
COPY . .
ENV GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local CGO_ENABLED=0
RUN go build -trimpath -o /out/api ./cmd/api

FROM nginx:1.28-bookworm@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
COPY --from=build /out/api /usr/local/bin/orders-api
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY scripts/start.sh /start.sh
# TLS material (cert.pem, key.pem, ca.pem) is mounted at /etc/orders-edge/tls at run time.
EXPOSE 8443
CMD ["/start.sh"]
