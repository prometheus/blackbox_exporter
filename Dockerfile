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

FROM debian:bullseye

RUN useradd -m blackbox

USER blackbox

COPY --from=builder /go/bin/blackbox_exporter /usr/bin

ADD blackbox.yml .

WORKDIR /apps

EXPOSE      9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/app/blackbox.yml" ]
