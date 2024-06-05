FROM golang:1.21-bullseye as builder

RUN apt update && \
    apt-get install -y \
        build-essential \
        ca-certificates \
        curl

WORKDIR /build

# cache dependencies.
COPY ./go.mod .
COPY ./go.sum .
RUN go mod download

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build go install -v ./...

RUN make build

FROM debian:bullseye

RUN useradd -m blackbox && \
    apt update && \
    apt install -y \
        ca-certificates \
        curl

USER blackbox

COPY --from=builder /go/bin/blackbox_exporter /bin

WORKDIR /apps

ADD blackbox.yml /etc/blackbox_exporter/config.yml

EXPOSE 9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]
