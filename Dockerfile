FROM golang:1.12 as builder

WORKDIR /go/src/github.com/prometheus/blackbox_exporter
ADD . .
RUN make

FROM quay.io/prometheus/busybox:latest
LABEL maintainer="The Prometheus Authors <prometheus-developers@googlegroups.com>"

COPY --from=builder /go/src/github.com/prometheus/blackbox_exporter/blackbox_exporter /bin/blackbox_exporter
COPY blackbox.yml /etc/blackbox_exporter/config.yml

EXPOSE      9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]
