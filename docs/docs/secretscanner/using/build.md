---
title: Build SecretScanner
---

# Build SecretScanner

SecretScanner is a self-contained docker-based tool. Clone the [SecretScanner repository](https://github.com/deepfence/SecretScanner), then build:

```bash
./bootstrap.sh
docker build --rm=true --tag=deepfenceio/deepfence_secret_scanner:2.0.0 -f Dockerfile .
```

Alternatively, you can pull the official deepfence image at `deepfenceio/deepfence_secret_scanner:2.0.0`:

```bash
docker pull deepfenceio/deepfence_secret_scanner:2.0.0
```