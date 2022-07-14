---
title: Command-Line Options
---

# Command Line Options

Display the command line options:

```bash
$ docker run -it --rm deepfenceio/deepfence-yaradare:latest --help
```

or, with a standalone build:

```bash
$ ./SecretScanner --help
```


# Configuring SecretScanner

```bash
$ ./SecretScanner --help

Usage of ./SecretScanner:
  -config-path string
    	Searches for config.yaml from given directory. If not set, tries to find it from SecretScanner binary's and current directory
  -debug-level string
    	Debug levels are one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG. Only levels higher than the debug-level are displayed (default "ERROR")
  -image-name string
    	Name of the image along with tag to scan for secrets
  -json-filename string
    	Output json file name. If not set, it will automatically create a filename based on image or dir name
  -local string
    	Specify local directory (absolute path) which to scan. Scans only given directory recursively.
  -max-multi-match uint
    	Maximum number of matches of same pattern in one file. This is used only when multi-match option is enabled. (default 3)
  -max-secrets uint
    	Maximum number of secrets to find in one container image or file system. (default 1000)
  -maximum-file-size uint
    	Maximum file size to process in KB (default 256)
  -multi-match
    	Output multiple matches of same pattern in one file. By default, only one match of a pattern is output for a file for better performance
  -output-path string
    	Output directory where json file will be stored. If not set, it will output to current directory
  -temp-directory string
    	Directory to process and store repositories/matches (default "/tmp")
  -threads int
    	Number of concurrent threads (default number of logical CPUs)
  -socket-path string
  		The gRPC server socket path
```