---
title: SecretScanner QuickStart
---

# Quick Start

Pull the latest SecretScanner image, and use it to scan a `node:latest` container.

## Pull the latest SecretScanner image

```bash
docker pull quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.0
```

## Generate License Key

Run this command to generate a license key. Work/official email id has to be used.
```shell
curl https://license.deepfence.io/threatmapper/generate-license?first_name=<FIRST_NAME>&last_name=<LAST_NAME>&email=<EMAIL>&company=<ORGANIZATION_NAME>&resend_email=true
```

## Scan a Container Image

Pull an image to your local repository, then scan it

```bash
docker pull node:latest

docker run -i --rm --name=deepfence-secretscanner \
    -e DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker> \
    -e DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key> \
	-v /var/run/docker.sock:/var/run/docker.sock \
	quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.0 \
	-image-name node:latest

docker rmi node:latest
```

Rules can also be cached to use next run by mounting a seperate path and passing `rules-path` argument
```shell
docker run -i --rm --name=deepfence-yarahunter \
     -e DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker> \
     -e DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key> \
     -v /var/run/docker.sock:/var/run/docker.sock \
     -v /tmp/rules:/tmp/rules \
     quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.0 \
     --image-name node:8.11 \
     --rules-path=/tmp/rules \
     --output json > node.json
```

## Process the results with jq

You can summarise the results by processing the JSON output, e.g. using `jq`:

```bash
docker run -i --rm --name=deepfence-secretscanner \
    -e DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker> \
    -e DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key> \
    -v /var/run/docker.sock:/var/run/docker.sock \
    quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.0 \
    --image-name node:latest \
    --output json > /tmp/node-secret-scan.json

cat /tmp/node-secret-scan.json | jq '.Secrets[] | { rule: ."Matched Rule Name", file: ."Full File Name" }'
```