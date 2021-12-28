FROM ubuntu:focal
MAINTAINER DeepFence

RUN echo 'tzdata tzdata/Areas select Etc' | debconf-set-selections \
    && echo 'tzdata tzdata/Zones/Etc select UTC' | debconf-set-selections \
    && apt-get update \
    && export DEBIAN_FRONTEND=noninteractive \
    && apt-get install -y git \
    && apt-get install -y --no-install-recommends gcc cmake make python3.9 build-essential libltdl7 pkg-config ragel libboost-dev wget nano \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /usr/local/include/ && \
    cd /usr/local/include/ && \
    git clone https://github.com/intel/hyperscan.git && \
    mkdir /usr/local/include/hs && \
    cd /usr/local/include/hs && \
    export MAKEFLAGS=-j$(nproc) && \
    cmake -DBUILD_STATIC_AND_SHARED=1 /usr/local/include/hyperscan && \
    echo "/usr/local/lib" | tee --append /etc/ld.so.conf.d/usrlocal.conf && \
    cd /usr/local/include/hs && make && make install
RUN wget https://go.dev/dl/go1.17.5.linux-amd64.tar.gz && \
    tar -C /usr/local -zxvf go1.17.5.linux-amd64.tar.gz && \
    mv /usr/local/go /usr/local/go-1.17.5 && \
    rm go1.17.5.linux-amd64.tar.gz && \
    mkdir /root/.go
ENV GOPATH=/root/.go \
    PKG_CONFIG_PATH=/usr/local/include/hs/ \
    CGO_CFLAGS="-I/usr/local/include/hyperscan/src" \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/local/include/hs/lib:$LD_LIBRARY_PATH \
    PATH=/usr/local/go-1.17.5/bin:~/.go/bin:$PATH

WORKDIR /home/deepfence/src/SecretScanner
COPY . .
RUN go build -v -i \
    && mv /home/deepfence/src/SecretScanner/SecretScanner /home/deepfence/src/SecretScanner/config.yaml /tmp \
    && rm -rf /home/deepfence/src/SecretScanner/* \
    && mv /tmp/SecretScanner /tmp/config.yaml /home/deepfence/src/SecretScanner \
    && rm -rf /usr/local/go-1.17.5
WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/src/SecretScanner/SecretScanner", "-config-path", "/home/deepfence/src/SecretScanner"]
CMD ["-h"]
