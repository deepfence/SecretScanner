---
title: Scan with SecretScanner
---

# Scanning with SecretScanner

You can use SecretScanner to scan running or at-rest container images, and local file systems.  SecretScanner will match the assets it finds against the secrets rules it has been configured with.

## Scan a Container Image

Pull the image to your local repository, then scan it

```bash
docker pull node:latest

docker run -it --rm --name=deepfence-secretscanner \
    -e DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker> \
    -e DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key> \
    -v /var/run/docker.sock:/var/run/docker.sock \
    quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.2 \
# highlight-next-line
    --image-name node:latest

docker rmi node:latest
```

### Scan a filesystem

Mount the filesystem within the SecretScanner container and scan it.  Here, we scan the contents of `/tmp` on the host:

```bash
docker run -it --rm --name=deepfence-secretscanner \
    -e DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker> \
    -e DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key> \
# highlight-next-line
    -v /tmp:/deepfence/mnt \
    quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.2 \
# highlight-next-line
    --host-mount-path /deepfence/mnt --local /deepfence/mnt 
```

Note that you can use nerdctl as an alternative to docker in the commands above.