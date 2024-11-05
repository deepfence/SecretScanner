ARG VECTORSCAN_IMG_TAG=latest
ARG VECTORSCAN_IMAGE_REPOSITORY=deepfenceio
FROM $VECTORSCAN_IMAGE_REPOSITORY/deepfence_vectorscan_build:$VECTORSCAN_IMG_TAG AS vectorscan

FROM golang:1.23-alpine3.20 AS builder
MAINTAINER DeepFence

RUN apk update  \
    && apk add --upgrade gcc musl-dev pkgconfig g++ make git

RUN apk add --no-cache \
    git \
    make  \
    build-base \
    pkgconfig \
    libpcap-dev \
    libcap-dev \
    openssl-dev \
    file \
    jansson-dev \
    jansson-static \
    bison \
    tini \
    su-exec

RUN apk add --no-cache -t .build-deps py-setuptools \
    openssl-libs-static \
    jansson-dev \
    build-base \
    libc-dev \
    file-dev \
    automake \
    autoconf \
    libtool \
    libcrypto3 \
    flex \
    git \
    libmagic-static \
    linux-headers

RUN cd /root && wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.tar.gz \
    && tar -zxf v4.3.2.tar.gz \
    && cd yara-4.3.2 \
    && ./bootstrap.sh \
    && ./configure --prefix=/usr/local/yara --disable-dotnet --enable-magic --enable-cuckoo --disable-shared --enable-static\
    && make \
    && make install \
    && cd /usr/local/ \
    && tar -czf yara.tar.gz yara

WORKDIR /home/deepfence/src/SecretScanner
COPY . .
RUN make clean && make all

FROM alpine:3.20
MAINTAINER DeepFence
LABEL deepfence.role=system

ENV MGMT_CONSOLE_URL=deepfence-internal-router \
    MGMT_CONSOLE_PORT=443

ARG TARGETARCH

RUN apk add --no-cache --upgrade tar libstdc++ libgcc docker skopeo bash podman

RUN <<EOF
set -eux

apk update && apk add --no-cache --upgrade curl

NERDCTL_VERSION=1.7.7
curl -fsSLO https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-${NERDCTL_VERSION}-linux-${TARGETARCH}.tar.gz
tar Cxzvvf /usr/local/bin nerdctl-${NERDCTL_VERSION}-linux-${TARGETARCH}.tar.gz
rm nerdctl-${NERDCTL_VERSION}-linux-${TARGETARCH}.tar.gz

apk del curl
EOF

WORKDIR /home/deepfence/usr
COPY --from=builder /home/deepfence/src/SecretScanner/SecretScanner .
COPY --from=builder /home/deepfence/src/SecretScanner/config.yaml .
WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/usr/SecretScanner", "-config-path", "/home/deepfence/usr"]
CMD ["-h"]
