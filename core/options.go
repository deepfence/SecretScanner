package core

import (
	"flag"
	"os"
)

const (
	TempDirSuffix          = "SecretScanning"
	ExtractedImageFilesDir = "ExtractedFiles"
)

type Options struct {
	Threads         *int
	DebugLevel      *string
	MaximumFileSize *uint
	TempDirectory   *string
	Local           *string
	HostMountPath   *string
	ConfigPath      *string
	OutputPath      *string
	JsonFilename    *string
	ImageName       *string
	MultipleMatch   *bool
	MaxMultiMatch   *uint
	MaxSecrets      *uint
	ContainerId     *string
	ContainerNS     *string
	Quiet			*bool
}

func ParseOptions() (*Options, error) {
	options := &Options{
		Threads:         flag.Int("threads", 0, "Number of concurrent threads (default number of logical CPUs)"),
		DebugLevel:      flag.String("debug-level", "ERROR", "Debug levels are one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG. Only levels higher than the debug-level are displayed"),
		MaximumFileSize: flag.Uint("maximum-file-size", 256, "Maximum file size to process in KB"),
		TempDirectory:   flag.String("temp-directory", os.TempDir(), "Directory to process and store repositories/matches"),
		Local:           flag.String("local", "", "Specify local directory (absolute path) which to scan. Scans only given directory recursively."),
		HostMountPath:   flag.String("host-mount-path", "", "If scanning the host, specify the host mount path for path exclusions to work correctly."),
		ConfigPath:      flag.String("config-path", "", "Searches for config.yaml from given directory. If not set, tries to find it from SecretScanner binary's and current directory"),
		OutputPath:      flag.String("output-path", ".", "Output directory where json file will be stored. If not set, it will output to current directory"),
		JsonFilename:    flag.String("json-filename", "", "Output json file name. If not set, it will automatically create a filename based on image or dir name"),
		ImageName:       flag.String("image-name", "", "Name of the image along with tag to scan for secrets"),
		MultipleMatch:   flag.Bool("multi-match", false, "Output multiple matches of same pattern in one file. By default, only one match of a pattern is output for a file for better performance"),
		MaxMultiMatch:   flag.Uint("max-multi-match", 3, "Maximum number of matches of same pattern in one file. This is used only when multi-match option is enabled."),
		MaxSecrets:      flag.Uint("max-secrets", 1000, "Maximum number of secrets to find in one container image or file system."),
		ContainerId:     flag.String("container-id", "", "Id of existing container ID"),
		ContainerNS:     flag.String("container-ns", "", "Namespace of existing container to scan, empty for docker runtime"),
		Quiet: 			 flag.Bool("quiet", false, "Don't display any output in stdout"),
	}
	flag.Parse()
	return options, nil
}
