ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

LABEL org.opencontainers.image.authors="The Prometheus Authors <prometheus-developers@googlegroups.com>" \
      org.opencontainers.image.vendor="Prometheus" \
      org.opencontainers.image.title="Blackbox Exporter" \
      org.opencontainers.image.description="Prometheus blackbox prober exporter" \
      org.opencontainers.image.source="https://github.com/prometheus/blackbox_exporter" \
      org.opencontainers.image.url="https://github.com/prometheus/blackbox_exporter" \
      org.opencontainers.image.documentation="https://github.com/prometheus/blackbox_exporter/blob/main/README.md" \
      org.opencontainers.image.licenses="Apache License 2.0"
      io.prometheus.image.variant="busybox"

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/blackbox_exporter  /bin/blackbox_exporter
COPY blackbox.yml       /etc/blackbox_exporter/config.yml

EXPOSE      9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]
