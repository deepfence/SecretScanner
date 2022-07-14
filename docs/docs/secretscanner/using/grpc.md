---
title: Using over GRPC
---

# Using over GRPC

You can run a persistent SecretScanner service and issue requests for scans using GRPC.  You first need to build SecretScanner from source, to generate the necessary proto files.

## Prerequisites

You will need the [grcpurl](https://github.com/fullstorydev/grpcurl) tool.


## Run the SecretScanner gRPC server

Start the SecretScanner gRPC server:

```bash
docker run -it --rm --name=deepfence-secretscanner \
	-v $(pwd):/home/deepfence/output \
	-v /var/run/docker.sock:/var/run/docker.sock \
	-v /tmp/sock:/tmp/sock \
	deepfenceio/deepfence_secret_scanner:latest \
	-socket-path /tmp/sock/s.sock
```

:::info

Currently testing this, determining how the secret_scanner.proto files are generated

:::


## Scan a Container Image

```bash
# run this from the repo directory, or update the import-path

grpcurl -plaintext -import-path ./agent-plugins-grpc/proto -proto secret_scanner.proto \
    -d '{"image": {"name": "node:latest"}}' \
    -unix '/tmp/sock.sock' \
    secret_scanner.SecretScanner/FindSecretInfo
```

## Scan a Local Directory

```bash
# run this from the repo directory, or update the import-path

grpcurl -plaintext -import-path ./agent-plugins-grpc/proto -proto secret_scanner.proto \
	-d '{"path": "/tmp"}' \
	-unix '/tmp/sock.sock' \
	secret_scanner.SecretScanner/FindSecretInfo
```

