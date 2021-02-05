Deepfence SecretScanner helps users to scan their container images or local directories for finding secrets like passwords, keys and tokens which are left inadvertently. It outputs a json file with details of all the secrets found.

# Build Instructions

1. Install Docker
2. Install Hyperscan
3. Install go for your platform (version 1.14)
4. Install go modules, if needed: gohs, yaml.v3 and color
5. `go get github.com/deepfence/SecretScanner` will download and build SecretScanner automatically in ~/.go/bin directory. Or, you can clone this repository and run `go build -v -i` to build the executable in current directory.
6. Edit your config.yaml file as needed and run the secret scanner with the appropriate config file directory. Please find more help on the usage below.

For reference, [Install file](https://github.com/deepfence/SecretScanner/blob/master/Install.Ubuntu) has the commands to build on ubuntu

# Docker Installations

For quick try, you can install docker and then run SecretScanner on a container image using following instructions

`docker build --rm=true --tag=deepfenceio/secretscanning:latest -f Dockerfile .`

`docker pull node:8.11`

`docker run -it --name=deepfence-secretscanner -v /var/run/docker.sock:/var/run/docker.sock -v /usr/bin/docker:/usr/bin/docker deepfenceio/secretscanning:latest -local /home/deepfence/src/SecretScanner/test -image-name node:8.11`

`docker cp deepfence-secretscanner:/home/deepfence/output temp-output/`

SecretScanner will create json files with the details of all the secrets found in the current working directory. In this case, output json files will be in the working directory (/home/deepfence/output) inside the container.

# Instructions to Run on Host

`./SecretScanner --help`

`./SecretScanner -config-path /path/to/config.yaml/dir -local test`

`./SecretScanner -config-path /path/to/config.yaml/dir -image-name node:8.11`

# Options
```
Usage of ./SecretScanner:
  -config-path string
    	Searches for config.yaml from given directory. If not set, tries to find it from SecretScanner binary's and current directory
  -debug-level string
    	Debug levels are one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG. Only levels higher than the debug-level are displayed (default "ERROR")
  -image-name string
    	Name of the image along with tag to scan for secrets
  -local string
    	Specify local directory (absolute path) which to scan. Scans only given directory recursively.
  -max-multi-match uint
    	Maximum number of matches of same pattern in one file. This is used only when multi-match option is enabled. (default 3)
  -maximum-file-size uint
    	Maximum file size to process in KB (default 256)
  -multi-match
    	Output multiple matches of same pattern in one file. By default, only one match of a pattern is output for a file for better performance
  -temp-directory string
    	Directory to process and store repositories/matches (default "/tmp/Deepfence/SecretScanning")
  -threads int
    	Number of concurrent threads (default number of logical CPUs)

```

# Credits

We have built upon the configuration file from [shhgit](https://github.com/eth0izzle/shhgit) project
