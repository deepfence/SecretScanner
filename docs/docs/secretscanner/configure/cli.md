---
title: Command-Line Options
---

# Command Line Options

Display the command line options:

```bash
$ docker run -it --rm deepfenceio/deepfence_secret_scanner:latest --help
```

or, with a standalone build:

```bash
$ ./SecretScanner --help
```


# Configuring SecretScanner


### General Configuration

 * `--debug bool`: print debug level logs.
 * `--threads int`: Number of concurrent threads to use during scan (default number of logical CPUs).
 * `--temp-directory string`: temporary storage for working data (default "/tmp")

 * `--max-secrets int`: Maximum number of secrets to report from a container image or file system (default 1000).
 * `--maximum-file-size int`: Maximum file size to process in Kb (default 256).
 * `-multi-match`: Output multiple matches of same pattern in one file. By default, only one match of a pattern is output for a file for better performance
 * `-max-multi-match int`: Maximum number of matches of same pattern in one file. This is used only when multi-match option is enabled (default 3)

### Scan Containers

 * `--image-name string`: scan this image (name:tag) in the local registry
 * `--container-id string`: scan a running container, identified by the provided container ID
 * `--container-ns string`: search the provided namespace (not used for Docker runtime)

### Scan Filesystems

 * `--local string`: scan the local directory in the SecretScanner docker container.  Mount the external (host) directory within the container using `-v`
 * `--host-mount-path string`: inform SecretScanner of the location in the container where the host filesystem was mounted, such as '/tmp/mnt'. SecretScanner uses this as the root directory when matching `exclude_paths` such as `/var/lib` (see below) 

### Configure Output

SecretScanner can write output as Table and JSON format

 * `-output`: Output format: json or table (default "table")

### Configure GRPC Listener

SocketScanner can run persistently, listening for scan requests over GRPC, either on an HTTP endpoint or a unix socket.

:::info

### Help needed!

This functionality is out-of-date and needs refreshed
:::

 * `--http-port string`: When set the http server will come up at port with df es as output
 * `--socket-path string`: The gRPC server unix socket path

 
### Configure Scans

Scans can be fine-tuned using settings in `config.yaml`:

 * `--config-path string`: directory location of `config.yaml`. If not set, SecretScanner will fall back to the local binary directory or the current working directory.

`config.yaml` can be used to exclude files and locations from the malware scan:

```yaml
# SecretScanner Configuration File

blacklisted_strings: [] # skip matches containing any of these strings (case sensitive)
blacklisted_extensions: [ ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".psd", ".xcf", ".zip", ".tar.gz", ".ttf", ".lock"] 
# need to confirm as windows hides file extensions
blacklisted_paths: ["/var/lib/docker", "/var/lib/containerd", "/bin", "/boot", "/dev", "/lib", "/lib64", "/media", "/proc", "/run", "/sbin", "/usr/lib", "/sys"] # use \ for windows paths
```

For other settings, refer to the [sample config.yaml file](https://github.com/deepfence/SecretScanner/tree/master/config.yaml)