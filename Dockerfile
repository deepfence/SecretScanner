#FROM debian:stretch-slim
FROM ubuntu:bionic
MAINTAINER DeepFence

RUN apt-get update && apt-get install -y git gcc cmake make build-essential python2.7 pkg-config ragel libboost-dev wget nano
RUN mkdir -p /usr/local/include/ && \
    cd /usr/local/include/ && \
    git clone https://github.com/intel/hyperscan.git && \
    mkdir /usr/local/include/hs && \
    cd /usr/local/include/hs && \
    cmake -DBUILD_STATIC_AND_SHARED=1 /usr/local/include/hyperscan && \
    echo "/usr/local/lib" | tee --append /etc/ld.so.conf.d/usrlocal.conf && \
    cd /usr/local/include/hs && make && make install
RUN wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz && \
    tar -C /usr/local -zxvf go1.14.2.linux-amd64.tar.gz && \
    mv /usr/local/go /usr/local/go-1.14.2 && \
    rm go1.14.2.linux-amd64.tar.gz && \
    mkdir /root/.go
ENV GOPATH=/root/.go \
    PKG_CONFIG_PATH=/usr/local/include/hs/ \
    CGO_CFLAGS="-I/usr/local/include/hyperscan/src" \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/local/include/hs/lib:$LD_LIBRARY_PATH \
    PATH=/usr/local/go-1.14.2/bin:~/.go/bin:$PATH
RUN go get "github.com/flier/gohs/hyperscan" "gopkg.in/yaml.v3" "github.com/fatih/color"
RUN go get "github.com/deepfence/SecretScanner"

RUN mkdir -p /home/deepfence/src
WORKDIR /home/deepfence/src
RUN git clone https://github.com/deepfence/SecretScanner.git
WORKDIR /home/deepfence/src/SecretScanner
RUN go build -v -i
WORKDIR /home/deepfence
RUN cp src/SecretScanner/SecretScanner .
