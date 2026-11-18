# CertKeeper server image.
#
# The build stage runs on the build machine's own architecture and cross-compiles a fully static
# binary for the target with Swift's static Linux SDK, so building an amd64 image on an ARM Mac
# (or the reverse) needs no emulation:
#
#   docker build --platform linux/amd64 -t certkeeper .

ARG SWIFT_IMAGE=swift:6.4.2-noble

FROM --platform=$BUILDPLATFORM ${SWIFT_IMAGE} AS build
ARG TARGETARCH
# Must match the toolchain version above.
ARG STATIC_SDK_URL=https://download.swift.org/swift-6.4.2-release/static-sdk/swift-6.4.2-RELEASE/swift-6.4.2-RELEASE_static-linux-0.1.0.artifactbundle.tar.gz
ARG STATIC_SDK_CHECKSUM=3786b179936d9cc9e266dd506bd1654176358d7b25288e243359f4d17cc4dc5a
RUN swift sdk install "$STATIC_SDK_URL" --checksum "$STATIC_SDK_CHECKSUM"
WORKDIR /src
COPY Package.swift Package.resolved ./
RUN swift package resolve
COPY Sources Sources
COPY Tests Tests
RUN case "$TARGETARCH" in \
      amd64) triple=x86_64-swift-linux-musl ;; \
      arm64) triple=aarch64-swift-linux-musl ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && swift build -c release --swift-sdk "$triple" --product certkeeper-server -Xlinker -s \
 && bin="$(swift build -c release --swift-sdk "$triple" --show-bin-path)" \
 && mkdir /out \
 && cp "$bin/certkeeper-server" /out/ \
 && cp -R "$bin/CertKeeper_CertKeeperServer.bundle" /out/

FROM debian:trixie-slim
# ssh to reach hosts, openssl for PKCS#12/PKCS#7 exports, curl for the health check, tini to reap
# the ssh processes CertKeeper starts (including ControlMaster helpers), nss_wrapper so ssh works
# under any uid (see UserEntry).
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-client openssl curl ca-certificates tini libnss-wrapper \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 568 apps \
 && useradd -u 568 -g 568 -d /config -M -s /usr/sbin/nologin apps \
 && mkdir -p /config && chown 568:568 /config
COPY --from=build /out/ /app/
COPY LICENSE NOTICE /app/

# All state lives in /config, which is also HOME so ssh keeps its key and known_hosts there.
ENV HOME=/config \
    CERTKEEPER_CONFIG_DIR=/config \
    CERTKEEPER_PORT=8443
USER 568:568
WORKDIR /config
VOLUME /config
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD curl -fsk "https://127.0.0.1:${CERTKEEPER_PORT}/healthz" || exit 1
# Give running deployments time to finish on stop (see ServerState.drain); pair with a stop grace
# period of at least 3 minutes.
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--", "/app/certkeeper-server"]

LABEL org.opencontainers.image.title="CertKeeper" \
      org.opencontainers.image.description="Let's Encrypt certificates for servers and devices: issued through Cloudflare DNS, deployed and renewed over SSH" \
      org.opencontainers.image.source="https://github.com/MJWaters1985/CertKeeper" \
      org.opencontainers.image.licenses="Apache-2.0"
