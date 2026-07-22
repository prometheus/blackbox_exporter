ARG ARCH="amd64"
ARG OS="linux"

# Install a current CA bundle independently of the busybox base image rebuild
# cycle. Blackbox probes remote TLS endpoints, so stale roots cause false
# probe failures (see #1429, #1547).
FROM debian:trixie-slim AS certs
RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

LABEL org.opencontainers.image.authors="The Prometheus Authors <prometheus-developers@googlegroups.com>"
LABEL org.opencontainers.image.vendor="Prometheus"
LABEL org.opencontainers.image.title="Blackbox Exporter"
LABEL org.opencontainers.image.description="Prometheus blackbox prober exporter"
LABEL org.opencontainers.image.source="https://github.com/prometheus/blackbox_exporter"
LABEL org.opencontainers.image.url="https://github.com/prometheus/blackbox_exporter"
LABEL org.opencontainers.image.documentation="https://github.com/prometheus/blackbox_exporter/blob/main/README.md"
LABEL org.opencontainers.image.licenses="Apache License 2.0"
LABEL io.prometheus.image.variant="busybox"

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/blackbox_exporter  /bin/blackbox_exporter
COPY blackbox.yml       /etc/blackbox_exporter/config.yml
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE      9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]
