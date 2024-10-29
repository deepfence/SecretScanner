package core

import (
	"flag"
	"os"
	"strings"

	"github.com/deepfence/YaraHunter/utils"
)

const (
	TempDirSuffix          = "SecretScanning"
	ExtractedImageFilesDir = "ExtractedFiles"
	JSONOutput             = "json"
	TableOutput            = "table"
)

var (
	product string = utils.GetEnvOrDefault("DEEPFENCE_PRODUCT", "ThreatMapper")
	license string = utils.GetEnvOrDefault("DEEPFENCE_LICENSE", "")
)

type Options struct {
	Threads              *int
	Debug                *bool
	MaximumFileSize      *uint
	TempDirectory        *string
	Local                *string
	HostMountPath        *string
	ConfigPath           *string
	RulesPath            *string
	RulesListingURL      *string
	FailOnCompileWarning *bool
	EnableUpdater        *bool
	MergeConfigs         *bool
	ImageName            *string
	MultipleMatch        *bool
	MaxMultiMatch        *uint
	MaxSecrets           *uint
	ContainerID          *string
	ContainerNS          *string
	WorkersPerScan       *int
	InactiveThreshold    *int
	OutFormat            *string
	ConsoleURL           *string
	ConsolePort          *int
	DeepfenceKey         *string
	FailOnCount          *int
	FailOnHighCount      *int
	FailOnMediumCount    *int
	FailOnLowCount       *int
	Product              *string
	License              *string
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
		Threads:              flag.Int("threads", 0, "Number of concurrent threads (default number of logical CPUs)"),
		Debug:                flag.Bool("debug", false, "enable debug logs"),
		MaximumFileSize:      flag.Uint("maximum-file-size", 256, "Maximum file size to process in KB"),
		TempDirectory:        flag.String("temp-directory", os.TempDir(), "Directory to process and store repositories/matches"),
		Local:                flag.String("local", "", "Specify local directory (absolute path) which to scan. Scans only given directory recursively."),
		HostMountPath:        flag.String("host-mount-path", "", "If scanning the host, specify the host mount path for path exclusions to work correctly."),
		ConfigPath:           flag.String("config-path", "", "yaml config path"),
		RulesPath:            flag.String("rules-path", "/home/deepfence/usr", "yara rules path"),
		RulesListingURL:      flag.String("rules-listing-url", "", "yara rules listing url"),
		FailOnCompileWarning: flag.Bool("fail-warning", false, "fail if compilation warning"),
		EnableUpdater:        flag.Bool("enable-updated", false, "Enable rule updater"),
		MergeConfigs:         flag.Bool("merge-configs", false, "Merge config files specified by --config-path into the default config"),
		ImageName:            flag.String("image-name", "", "Name of the image along with tag to scan for secrets"),
		MultipleMatch:        flag.Bool("multi-match", false, "Output multiple matches of same pattern in one file. By default, only one match of a pattern is output for a file for better performance"),
		MaxMultiMatch:        flag.Uint("max-multi-match", 3, "Maximum number of matches of same pattern in one file. This is used only when multi-match option is enabled."),
		MaxSecrets:           flag.Uint("max-secrets", 1000, "Maximum number of secrets to find in one container image or file system."),
		ContainerID:          flag.String("container-id", "", "Id of existing container ID"),
		ContainerNS:          flag.String("container-ns", "", "Namespace of existing container to scan, empty for docker runtime"),
		WorkersPerScan:       flag.Int("workers-per-scan", 1, "Number of concurrent workers per scan"),
		InactiveThreshold:    flag.Int("inactive-threshold", 600, "Threshold for Inactive scan in seconds"),
		OutFormat:            flag.String("output", TableOutput, "Output format: json or table"),
		ConsoleURL:           flag.String("console-url", "", "Deepfence Management Console URL"),
		ConsolePort:          flag.Int("console-port", 443, "Deepfence Management Console Port"),
		DeepfenceKey:         flag.String("deepfence-key", "", "Deepfence key for auth"),
		FailOnCount:          flag.Int("fail-on-count", -1, "Exit with status 1 if number of secrets found is >= this value (Default: -1)"),
		FailOnHighCount:      flag.Int("fail-on-high-count", -1, "Exit with status 1 if number of high secrets found is >= this value (Default: -1)"),
		FailOnMediumCount:    flag.Int("fail-on-medium-count", -1, "Exit with status 1 if number of medium secrets found is >= this value (Default: -1)"),
		FailOnLowCount:       flag.Int("fail-on-low-count", -1, "Exit with status 1 if number of low secrets found is >= this value (Default: -1)"),
		Product:              flag.String("product", product, "Deepfence Product type can be ThreatMapper or ThreatStryker, also supports env var DEEPFENCE_PRODUCT"),
		License:              flag.String("license", license, "TheratMapper or ThreatStryker license, also supports env var DEEPFENCE_LICENSE"),
	}
	flag.Parse()
	return options, nil
}
