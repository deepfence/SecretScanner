FROM golang:1.19-alpine3.17 AS builder
MAINTAINER DeepFence

RUN apk update  \
    && apk add --upgrade gcc musl-dev pkgconfig g++ make git protoc \
    && apk add hyperscan-dev --repository=https://dl-cdn.alpinelinux.org/alpine/v3.13/community
ENV PKG_CONFIG_PATH=/usr/local/include/hs/ \
    CGO_CFLAGS="-I/usr/local/include/hyperscan/src" \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/local/include/hs/lib:$LD_LIBRARY_PATH

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28.1 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0

WORKDIR /home/deepfence/src/SecretScanner
COPY . .
RUN make clean
RUN make

FROM alpine:3.17
MAINTAINER DeepFence
LABEL deepfence.role=system

ENV MGMT_CONSOLE_URL=deepfence-internal-router \
    MGMT_CONSOLE_PORT=443
RUN apk update && apk add --no-cache --upgrade curl tar libstdc++ libgcc docker skopeo python3 py3-pip bash podman \
    && apk add hyperscan --repository=https://dl-cdn.alpinelinux.org/alpine/v3.13/community \
    && curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v1.1.0/nerdctl-1.1.0-linux-amd64.tar.gz \
    && tar Cxzvvf /usr/local/bin nerdctl-1.1.0-linux-amd64.tar.gz \
    && rm nerdctl-1.1.0-linux-amd64.tar.gz \
    && apk del curl
WORKDIR /home/deepfence/usr
COPY --from=builder /home/deepfence/src/SecretScanner/SecretScanner .
COPY --from=builder /home/deepfence/src/SecretScanner/config.yaml .
COPY registry_image_save/* ./
RUN pip3 install -r requirements.txt
WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/usr/SecretScanner", "-config-path", "/home/deepfence/usr", "-quiet"]
CMD ["-h"]
