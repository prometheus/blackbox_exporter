ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/blackbox_exporter  /bin/blackbox_exporter
RUN chmod +x /bin/blackbox_exporter
COPY blackbox.yml       /etc/blackbox_exporter/config.yml

EXPOSE 9115
ENTRYPOINT [ "/bin/blackbox_exporter" ]
CMD [ "--config.file=/etc/blackbox_exporter/config.yml" ]
# ARG ARCH="amd64"
# ARG OS="linux"
# FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
# LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

# ARG ARCH="amd64"
# ARG OS="linux"
# COPY .build/${OS}-${ARCH}/blackbox_exporter  /bin/blackbox_exporter
# COPY blackbox.yml       /etc/blackbox_exporter/config.yml

# EXPOSE      9115
# ENTRYPOINT  [ "/bin/blackbox_exporter" ]
# CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]
