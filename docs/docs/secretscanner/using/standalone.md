---
title: Standalone Build
---

# Running SecretScanner standalone


As an alternative to running SecretScanner as a docker container, you can build it as a Standalone application.

:::info

### Help needed!

These instructions are out-of-date and need refreshed
:::

## Build Instructions

1. Run bootstrap.sh
2. Install Docker
3. Install Hyperscan
4. Install go for your platform (version 1.14)
5. Install go modules, if needed: `gohs`, `yaml.v3` and `color`
6. `go get github.com/deepfence/SecretScanner` will download and build SecretScanner automatically in `$GOPATH/bin` or `$HOME/go/bin` directory. Or, clone this repository and run `go build -v -i` to build the executable in the current directory.
7. Edit config.yaml file as needed and run the secret scanner with the appropriate config file directory.

Refer to the [Install file](https://github.com/deepfence/SecretScanner/blob/master/Install.Ubuntu) for instructions on how to build on an ubuntu system.

## Instructions to Run on Local Host

### As a standalone application

```bash
./SecretScanner --help

./SecretScanner -config-path /path/to/config.yaml/dir -local test

./SecretScanner -config-path /path/to/config.yaml/dir -image-name node:8.11
```

### As a server application
```bash
./SecretScanner -socket-path /path/to/socket.sock
```
