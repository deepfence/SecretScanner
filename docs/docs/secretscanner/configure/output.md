---
title: Configure Output
---

# Configure Output

SecretScanner can writes output to `stdout` it can redirected to a file for further analysis.

```bash
# Write output to ./tmp/node-secret-scan.json

docker run -it --rm --name=deepfence_secret_scanner \
    -v /var/run/docker.sock:/var/run/docker.sock \
    deepfenceio/deepfence_secret_scanner:latest \
    --image-name node:latest \
# highlight-next-line
    --output json > ./tmp/node-secret-scan.json
```

