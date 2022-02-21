FROM golang:1.17-alpine3.13 AS builder
MAINTAINER DeepFence

RUN apk update && apk add --upgrade hyperscan-dev gcc musl-dev pkgconfig g++ make git protoc
ENV PKG_CONFIG_PATH=/usr/local/include/hs/ \
    CGO_CFLAGS="-I/usr/local/include/hyperscan/src" \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/local/include/hs/lib:$LD_LIBRARY_PATH

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1

WORKDIR /home/deepfence/src/
RUN git clone https://github.com/containerd/nerdctl
WORKDIR /home/deepfence/src/nerdctl
RUN make

WORKDIR /home/deepfence/src/SecretScanner
COPY . .
RUN make clean
RUN make

FROM alpine:3.13
MAINTAINER DeepFence

ENV MGMT_CONSOLE_URL=deepfence-fetcher \
    MGMT_CONSOLE_PORT=8006
RUN apk update && apk add --upgrade libstdc++ libgcc docker hyperscan skopeo python3 bash
WORKDIR /home/deepfence/usr
COPY --from=builder /home/deepfence/src/nerdctl/_output/nerdctl /bin
COPY --from=builder /home/deepfence/src/SecretScanner/SecretScanner .
COPY --from=builder /home/deepfence/src/SecretScanner/config.yaml .
WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/usr/SecretScanner", "-config-path", "/home/deepfence/usr"]
CMD ["-h"]
