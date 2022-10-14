package core

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

type Config struct {
	BlacklistedStrings           []string          `yaml:"blacklisted_strings"`
	BlacklistedExtensions        []string          `yaml:"blacklisted_extensions"`
	BlacklistedPaths             []string          `yaml:"blacklisted_paths"`
	BlacklistedEntropyExtensions []string          `yaml:"blacklisted_entropy_extensions"`
	Signatures                   []ConfigSignature `yaml:"signatures"`
}

type ConfigSignature struct {
	Name          string `yaml:"name"`
	Part          string `yaml:"part"`
	Match         string `yaml:"match,omitempty"`
	Regex         string `yaml:"regex,omitempty"`
	RegexType     string `yaml:"regextype,omitempty"`
	CompiledRegex *regexp.Regexp
	Verifier      string  `yaml:"verifier,omitempty"`
	Severity      string  `yaml:"severity,omitempty"`
	SeverityScore float64 `yaml:"severityscore,omitempty"`
	ID            int     `yaml:"ID,omitempty"`
}

func (c *Config) Merge(in *Config) {
	c.BlacklistedStrings = mergeStringSlices(c.BlacklistedStrings, in.BlacklistedStrings)
	c.BlacklistedExtensions = mergeStringSlices(c.BlacklistedExtensions, in.BlacklistedExtensions)
	c.BlacklistedPaths = mergeStringSlices(c.BlacklistedPaths, in.BlacklistedPaths)
	c.BlacklistedEntropyExtensions = mergeStringSlices(c.BlacklistedEntropyExtensions, in.BlacklistedEntropyExtensions)

	signatureNames := make(map[string]bool, len(c.Signatures))
	for _, sig := range c.Signatures {
		signatureNames[sig.Name] = true
	}
	for _, sig := range in.Signatures {
		if _, exists := signatureNames[sig.Name]; exists {
			for i, eSig := range c.Signatures {
				if sig.Name == eSig.Name {
					c.Signatures[i] = sig
					break
				}
			}
		} else {
			c.Signatures = append(c.Signatures, sig)
		}
	}
}

func mergeStringSlices(old, new []string) []string {
	m := make(map[string]bool, len(old))
	for _, s := range old {
		m[s] = true
	}

	for _, s := range new {
		if _, ok := m[s]; !ok {
			old = append(old, s)
		}
	}

	return old
}

func ParseConfig(options *Options) (*Config, error) {
	configFileDirs := options.ConfigPath.Values()

	if len(configFileDirs) > 0 {
		if *options.MergeConfigs {
			// merge them together onto default config in order of specification
			config, err := getDefaultConfig()
			if err != nil {
				return nil, err
			}

			var subConfig *Config
			for _, dir := range configFileDirs {
				subConfig, err = loadConfigFile(dir)
				if err != nil {
					return nil, err
				}
				config.Merge(subConfig)
			}

			return config, nil
		} else {
			if len(configFileDirs) > 1 {
				return nil, fmt.Errorf("error: Multiple config paths specified, but --merge-configs is not specified")
			}

			return loadConfigFile(configFileDirs[0])
		}

	}

	return getDefaultConfig()
}

// Trying to first find the configuration next to executable
// Helps e.g. with Drone where workdir is different than shhgit dir
func getDefaultConfig() (*Config, error) {
	ex, err := os.Executable()
	dir := filepath.Dir(ex)
	config, err := loadConfigFile(dir)
	if err != nil {
		dir, _ = os.Getwd()
		return loadConfigFile(dir)
	}
	return config, nil
}

func loadConfigFile(dir string) (*Config, error) {
	config := &Config{}

	data, err := ioutil.ReadFile(path.Join(dir, "config.yaml"))
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = Config{}
	type plain Config

	err := unmarshal((*plain)(c))

	if err != nil {
		return err
	}

	return nil
}
