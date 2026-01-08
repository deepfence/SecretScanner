ARG VECTORSCAN_IMG_TAG=latest
ARG VECTORSCAN_IMAGE_REPOSITORY=deepfenceio
FROM $VECTORSCAN_IMAGE_REPOSITORY/deepfence_vectorscan_build:$VECTORSCAN_IMG_TAG AS vectorscan

FROM golang:1.25-alpine3.23 AS builder
LABEL maintainer="DeepFence"

RUN apk update  \
    && apk add --upgrade gcc musl-dev pkgconfig g++ make git curl

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

RUN cd /root && wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.5.tar.gz \
    && tar -zxf v4.5.5.tar.gz \
    && cd yara-4.5.5 \
    && ./bootstrap.sh \
    && ./configure --prefix=/usr/local/yara --disable-dotnet --enable-magic --enable-cuckoo --disable-shared --enable-static\
    && make \
    && make install \
    && cd /usr/local/ \
    && tar -czf yara.tar.gz yara

# Copy YaraHunter first (for local replace directive)
WORKDIR /home/deepfence/src
COPY YaraHunter/ YaraHunter/

WORKDIR /home/deepfence/src/SecretScanner
COPY SecretScanner/ .
RUN make clean && make all

# Download rules and convert to yar format
RUN mkdir -p /home/deepfence/rules \
    && curl -fsSL https://artifacts.threatmapper.org/threat-intel/secret/secret_v2.5.8.tar.gz \
    -o /tmp/secret_rules.tar.gz \
    && tar -xzf /tmp/secret_rules.tar.gz -C /home/deepfence/rules --strip-components=1 \
    && rm /tmp/secret_rules.tar.gz

# Build and run the converter
WORKDIR /home/deepfence/src/SecretScanner
RUN go run ./cmd/convert-rules/main.go /home/deepfence/rules/df-secret.json /home/deepfence/rules/secret.yar


FROM alpine:3.23
LABEL maintainer="DeepFence"
LABEL deepfence.role=system

ENV MGMT_CONSOLE_URL=deepfence-internal-router \
    MGMT_CONSOLE_PORT=443

ARG TARGETARCH

RUN apk add --no-cache --upgrade tar libstdc++ libgcc docker skopeo bash podman curl

RUN <<EOF
set -eux

NERDCTL_VERSION=2.2.0
curl -fsSLO https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-${NERDCTL_VERSION}-linux-${TARGETARCH}.tar.gz
tar Cxzvvf /usr/local/bin nerdctl-${NERDCTL_VERSION}-linux-${TARGETARCH}.tar.gz
rm nerdctl-${NERDCTL_VERSION}-linux-${TARGETARCH}.tar.gz

EOF

WORKDIR /home/deepfence/usr
COPY --from=builder /home/deepfence/src/SecretScanner/SecretScanner .
COPY --from=builder /home/deepfence/src/SecretScanner/config.yaml .
COPY --from=builder /home/deepfence/rules/secret.yar .
WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/usr/SecretScanner", "-config-path", "/home/deepfence/usr", "-rules-path", "/home/deepfence/usr"]
CMD ["-h"]
