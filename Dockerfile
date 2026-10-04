# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/hysui ./cmd/hysui

# Runs as root: the VPN binds UDP 443 and Let's Encrypt's HTTP check needs port 80.
FROM gcr.io/distroless/static-debian13
COPY --from=build /out/hysui /usr/local/bin/hysui
ENV HYSUI_DATA_DIR=/data
VOLUME /data
EXPOSE 443/udp 8080/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/usr/local/bin/hysui", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/hysui"]
CMD ["serve"]
