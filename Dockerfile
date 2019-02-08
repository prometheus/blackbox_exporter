FROM  quay.io/prometheus/busybox:latest

FROM  scratch
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

COPY --from=0 /etc/ssl/certs     /etc/ssl/certs
COPY          blackbox_exporter  /bin/blackbox_exporter
COPY          blackbox.yml       /etc/blackbox_exporter/config.yml

EXPOSE      9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]
