---
title: Configure Output
---

# Configure Output

SecretScanner can write its JSON output to a container-local file (`--json-file`).

By default, the output is written to `/home/deepfence/output` in the container filesystem.  You can mount a host directory over this location.

```bash
# Write output to ./my-output/node-secret-scan.json

mkdir ./my-output

docker run -it --rm --name=deepfence_secret_scanner \
    -v /var/run/docker.sock:/var/run/docker.sock \
# highlight-next-line
    -v $(pwd)/my-output:/home/deepfence/output \
    deepfenceio/deepfence_secret_scanner:latest --image-name node:latest \
# highlight-next-line
    --json-file node-secret-scan.json
```

You can also override the default output location (`--output-path`) in the container.