package core

import (
	"flag"
	"os"
	"strings"
)

const (
	TempDirSuffix          = "SecretScanning"
	ExtractedImageFilesDir = "ExtractedFiles"
	JsonOutput             = "json"
	TableOutput            = "table"
)

type Options struct {
	Threads           *int
	DebugLevel        *string
	MaximumFileSize   *uint
	TempDirectory     *string
	Local             *string
	HostMountPath     *string
	ConfigPath        *repeatableStringValue
	MergeConfigs      *bool
	ImageName         *string
	MultipleMatch     *bool
	MaxMultiMatch     *uint
	MaxSecrets        *uint
	ContainerId       *string
	ContainerNS       *string
	WorkersPerScan    *int
	InactiveThreshold *int
	OutFormat         *string
	ConsoleUrl        *string
	ConsolePort       *int
	DeepfenceKey      *string
	FailOnCount       *int
	FailOnHighCount   *int
	FailOnMediumCount *int
	FailOnLowCount    *int
}

type repeatableStringValue struct {
	values []string
}

func (v *repeatableStringValue) String() string {
	return strings.Join(v.values, ", ")
}

func (v *repeatableStringValue) Set(s string) error {
	v.values = append(v.values, s)
	return nil
}

func (v *repeatableStringValue) Values() []string {
	return v.values
}

func ParseOptions() (*Options, error) {
	options := &Options{
		Threads:           flag.Int("threads", 0, "Number of concurrent threads (default number of logical CPUs)"),
		DebugLevel:        flag.String("debug-level", "ERROR", "Debug levels are one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG. Only levels higher than the debug-level are displayed"),
		MaximumFileSize:   flag.Uint("maximum-file-size", 256, "Maximum file size to process in KB"),
		TempDirectory:     flag.String("temp-directory", os.TempDir(), "Directory to process and store repositories/matches"),
		Local:             flag.String("local", "", "Specify local directory (absolute path) which to scan. Scans only given directory recursively."),
		HostMountPath:     flag.String("host-mount-path", "", "If scanning the host, specify the host mount path for path exclusions to work correctly."),
		ConfigPath:        &repeatableStringValue{},
		MergeConfigs:      flag.Bool("merge-configs", false, "Merge config files specified by --config-path into the default config"),
		ImageName:         flag.String("image-name", "", "Name of the image along with tag to scan for secrets"),
		MultipleMatch:     flag.Bool("multi-match", false, "Output multiple matches of same pattern in one file. By default, only one match of a pattern is output for a file for better performance"),
		MaxMultiMatch:     flag.Uint("max-multi-match", 3, "Maximum number of matches of same pattern in one file. This is used only when multi-match option is enabled."),
		MaxSecrets:        flag.Uint("max-secrets", 1000, "Maximum number of secrets to find in one container image or file system."),
		ContainerId:       flag.String("container-id", "", "Id of existing container ID"),
		ContainerNS:       flag.String("container-ns", "", "Namespace of existing container to scan, empty for docker runtime"),
		WorkersPerScan:    flag.Int("workers-per-scan", 1, "Number of concurrent workers per scan"),
		InactiveThreshold: flag.Int("inactive-threshold", 1200, "Threshold for Inactive scan in seconds"),
		OutFormat:         flag.String("output", TableOutput, "Output format: json or table"),
		ConsoleUrl:        flag.String("console-url", "", "Deepfence Management Console URL"),
		ConsolePort:       flag.Int("console-port", 443, "Deepfence Management Console Port"),
		DeepfenceKey:      flag.String("deepfence-key", "", "Deepfence key for auth"),
		FailOnCount:       flag.Int("fail-on-count", -1, "Exit with status 1 if number of secrets found is >= this value (Default: -1)"),
		FailOnHighCount:   flag.Int("fail-on-high-count", -1, "Exit with status 1 if number of high secrets found is >= this value (Default: -1)"),
		FailOnMediumCount: flag.Int("fail-on-medium-count", -1, "Exit with status 1 if number of medium secrets found is >= this value (Default: -1)"),
		FailOnLowCount:    flag.Int("fail-on-low-count", -1, "Exit with status 1 if number of low secrets found is >= this value (Default: -1)"),
	}
	flag.Var(options.ConfigPath, "config-path", "Searches for config.yaml from given directory. If not set, tries to find it from SecretScanner binary's and current directory.  Can be specified multiple times.")
	flag.Parse()
	return options, nil
}
