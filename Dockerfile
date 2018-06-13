FROM golang:alpine as build

RUN apk add --update git gcc make musl-dev

RUN mkdir -p /go/src/github.com/prometheus/ && \
    cd /go/src/github.com/prometheus/ && \
    git clone https://github.com/prometheus/blackbox_exporter.git && \
    cd blackbox_exporter && make build

FROM quay.io/prometheus/busybox:latest
LABEL Maintainer="prometheus-developers@googlegroups.com"

COPY --from=build /go/src/github.com/prometheus/blackbox_exporter/blackbox_exporter /bin/blackbox_exporter
COPY --from=build /go/src/github.com/prometheus/blackbox_exporter/blackbox.yml /etc/blackbox_exporter/config.yml

EXPOSE 9115
ENTRYPOINT [ "/bin/blackbox_exporter" ]
CMD [ "--config.file=/etc/blackbox_exporter/config.yml" ]
