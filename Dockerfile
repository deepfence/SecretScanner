FROM golang:1.17-alpine3.13 AS builder
MAINTAINER DeepFence

RUN apk update && apk add --upgrade hyperscan-dev gcc musl-dev pkgconfig g++
ENV GOPATH=/root/.go \
    PKG_CONFIG_PATH=/usr/local/include/hs/ \
    CGO_CFLAGS="-I/usr/local/include/hyperscan/src" \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/local/include/hs/lib:$LD_LIBRARY_PATH \
    PATH=/usr/local/go-1.17.5/bin:~/.go/bin:$PATH

WORKDIR /home/deepfence/src/SecretScanner
COPY . .
RUN go build -v -i

FROM alpine:3.13
MAINTAINER DeepFence

RUN apk update && apk add --upgrade libstdc++ libgcc docker hyperscan
WORKDIR /home/deepfence/usr
COPY --from=builder /home/deepfence/src/SecretScanner/SecretScanner .
COPY --from=builder /home/deepfence/src/SecretScanner/config.yaml .
WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/usr/SecretScanner", "-config-path", "/home/deepfence/usr"]
CMD ["-h"]
