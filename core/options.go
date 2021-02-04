package core

import (
	"flag"
	"os"
	"path/filepath"
)

const (
	TempDirName = "Deepfence/SecretScanning"
)

type Options struct {
	Threads          *int
	DebugLevel       *string
	MaximumFileSize  *uint
	TempDirectory    *string
	Local            *string
	ConfigPath       *string
	ImageName        *string
	MultipleMatch    *bool
	MaxMultiMatch    *uint
}

func ParseOptions() (*Options, error) {
	options := &Options{
		Threads:             flag.Int("threads", 0, "Number of concurrent threads (default number of logical CPUs)"),
		DebugLevel:          flag.String("debug-level", "ERROR", "Debug levels are one of FATAL, ERROR, IMPORTANT, WARN, INFO, DEBUG. Only levels higher than the debug-level are displayed"),
		MaximumFileSize:     flag.Uint("maximum-file-size", 256, "Maximum file size to process in KB"),
		TempDirectory:       flag.String("temp-directory", filepath.Join(os.TempDir(), TempDirName), "Directory to process and store repositories/matches"),
		Local:               flag.String("local", "", "Specify local directory (absolute path) which to scan. Scans only given directory recursively."),
		ConfigPath:          flag.String("config-path", "", "Searches for config.yaml from given directory. If not set, tries to find it from SecretScanner binary's and current directory"),
		ImageName:           flag.String("image-name", "", "Name of the image along with tag to scan for secrets"),
		MultipleMatch:       flag.Bool("multi-match", false, "Output multiple matches of same pattern in one file. By default, only one match of a pattern is output for a file for better performance"),
		MaxMultiMatch:       flag.Uint("max-multi-match", 3, "Maximum number of matches of same pattern in one file. This is used only when multi-match option is enabled."),
	}
	flag.Parse()
	return options, nil
}
