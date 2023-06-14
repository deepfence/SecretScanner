FROM golang:1.20-alpine3.18 AS builder
MAINTAINER DeepFence

RUN apk update  \
    && apk add --upgrade gcc musl-dev pkgconfig g++ make git protoc \
    && apk add hyperscan-dev --repository=https://dl-cdn.alpinelinux.org/alpine/v3.13/community
ENV PKG_CONFIG_PATH=/usr/local/include/hs/ \
    CGO_CFLAGS="-I/usr/local/include/hyperscan/src" \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/local/include/hs/lib:$LD_LIBRARY_PATH

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.30.0 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

WORKDIR /home/deepfence/src/SecretScanner
COPY . .
RUN make clean
RUN make

FROM alpine:3.18
MAINTAINER DeepFence
LABEL deepfence.role=system

ENV MGMT_CONSOLE_URL=deepfence-internal-router \
    MGMT_CONSOLE_PORT=443
RUN apk update && apk add --no-cache --upgrade curl tar libstdc++ libgcc docker skopeo bash podman \
    && apk add hyperscan --repository=https://dl-cdn.alpinelinux.org/alpine/v3.13/community \
    && nerdctl_version=1.4.0 \
    && curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v${nerdctl_version}/nerdctl-${nerdctl_version}-linux-amd64.tar.gz \
    && tar Cxzvvf /usr/local/bin nerdctl-${nerdctl_version}-linux-amd64.tar.gz \
    && rm nerdctl-${nerdctl_version}-linux-amd64.tar.gz \
    && apk del curl
WORKDIR /home/deepfence/usr
COPY --from=builder /home/deepfence/src/SecretScanner/SecretScanner .
COPY --from=builder /home/deepfence/src/SecretScanner/config.yaml .
WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/usr/SecretScanner", "-config-path", "/home/deepfence/usr", "-quiet"]
CMD ["-h"]
