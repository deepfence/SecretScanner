FROM golang:1.20-alpine3.18 AS builder
MAINTAINER DeepFence

RUN apk update  \
    && apk add --upgrade gcc musl-dev pkgconfig g++ make git vectorscan-dev

WORKDIR /home/deepfence/src/SecretScanner
COPY . .
RUN make clean
RUN make

FROM alpine:3.18
MAINTAINER DeepFence
LABEL deepfence.role=system

ENV MGMT_CONSOLE_URL=deepfence-internal-router \
    MGMT_CONSOLE_PORT=443

ARG TARGETARCH

RUN apk add --no-cache --upgrade tar libstdc++ libgcc docker skopeo bash podman

RUN <<EOF
set -eux

apk update && apk add --no-cache --upgrade curl 

NERDCTL_VERSION=1.4.0
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
