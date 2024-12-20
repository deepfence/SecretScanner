---
title: Build SecretScanner
---

# Build SecretScanner

SecretScanner is a self-contained docker-based tool. Clone the [SecretScanner repository](https://github.com/deepfence/SecretScanner), then build:

```bash
./bootstrap.sh
docker build --rm=true --tag=quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.2 -f Dockerfile .
```

Alternatively, you can pull the official Deepfence image at `quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.2`:

```bash
docker pull quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.2
```