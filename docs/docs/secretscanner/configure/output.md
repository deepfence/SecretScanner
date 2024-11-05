---
title: Configure Output
---

# Configure Output

SecretScanner can writes output to `stdout` it can redirected to a file for further analysis.

```bash
# Write output to ./tmp/node-secret-scan.json

docker run -it --rm --name=deepfence_secret_scanner \
    -e DEEPFENCE_PRODUCT=<ThreatMapper or ThreatStryker> \
    -e DEEPFENCE_LICENSE=<ThreatMapper or ThreatStryker license key> \
    -v /var/run/docker.sock:/var/run/docker.sock \
    quay.io/deepfenceio/deepfence_secret_scanner_ce:2.5.0 \
    --image-name node:latest \
# highlight-next-line
    --output json > ./tmp/node-secret-scan.json
```

