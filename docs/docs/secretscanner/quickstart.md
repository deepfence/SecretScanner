---
title: SecretScanner QuickStart
---

# Quick Start

Pull the latest SecretScanner image, and use it to scan a `node:latest` container.

## Pull the latest SecretScanner image

```bash
docker pull quay.io/deepfenceio/deepfence_secret_scanner_ce:2.4.0
```

## Scan a Container Image

Pull an image to your local repository, then scan it

```bash
docker pull node:latest

docker run -i --rm --name=deepfence-secretscanner \
	-v /var/run/docker.sock:/var/run/docker.sock \
	quay.io/deepfenceio/deepfence_secret_scanner_ce:2.4.0 \
	-image-name node:latest

docker rmi node:latest
```

## Process the results with jq

You can summarise the results by processing the JSON output, e.g. using `jq`:

```bash
docker run -i --rm --name=deepfence-secretscanner \
    -v /var/run/docker.sock:/var/run/docker.sock \
    quay.io/deepfenceio/deepfence_secret_scanner_ce:2.4.0 \
    --image-name node:latest \
    --output json > /tmp/node-secret-scan.json

cat /tmp/node-secret-scan.json | jq '.Secrets[] | { rule: ."Matched Rule Name", file: ."Full File Name" }'
```