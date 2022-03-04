FROM golang:1.17-alpine3.13 AS builder
MAINTAINER DeepFence

RUN apk update && apk add --upgrade hyperscan-dev gcc musl-dev pkgconfig g++ make git protoc
ENV PKG_CONFIG_PATH=/usr/local/include/hs/ \
    CGO_CFLAGS="-I/usr/local/include/hyperscan/src" \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/local/include/hs/lib:$LD_LIBRARY_PATH

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1

WORKDIR /home/deepfence/src/SecretScanner
COPY . .
RUN make clean
RUN make

FROM alpine:3.13
MAINTAINER DeepFence
LABEL deepfence.role=system

ENV MGMT_CONSOLE_URL=deepfence-fetcher \
    MGMT_CONSOLE_PORT=8006
RUN apk update && apk add --no-cache --upgrade curl tar libstdc++ libgcc docker hyperscan skopeo python3 py3-pip bash \
    && curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v0.17.1/nerdctl-0.17.1-linux-amd64.tar.gz \
    && tar Cxzvvf /usr/local/bin nerdctl-0.17.1-linux-amd64.tar.gz \
    && rm nerdctl-0.17.1-linux-amd64.tar.gz \
    && apk del curl
WORKDIR /home/deepfence/usr
COPY --from=builder /home/deepfence/src/SecretScanner/SecretScanner .
COPY --from=builder /home/deepfence/src/SecretScanner/config.yaml .
COPY registry_image_save/* ./
RUN pip3 install -r requirements.txt
WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/usr/SecretScanner", "-config-path", "/home/deepfence/usr"]
CMD ["-h"]
