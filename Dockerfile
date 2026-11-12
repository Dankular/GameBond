FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY native-edge/ ./
RUN GOFLAGS=-buildvcs=false CGO_ENABLED=0 GOOS=linux go build -o /out/gamebond-native-edge ./cmd/edge

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 nftables tini jq \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/gamebond-native-edge /usr/local/bin/gamebond-native-edge
COPY tools/container-entrypoint.sh /usr/local/bin/container-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/container-entrypoint && chmod 0755 /usr/local/bin/container-entrypoint
ENV GAMEBOND_NATIVE_EDGE=1
EXPOSE 4433/udp
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/container-entrypoint"]
