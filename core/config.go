package core

import (
	"os"
	"path/filepath"
	"regexp"

	"github.com/deepfence/match-scanner/pkg/config"
)

type Config struct {
	Signatures []ConfigSignature `yaml:"signatures"`
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

func loadExtractorConfigFile(options *Options) (config.Config, error) {
	configPath := *options.ConfigPath
	fstat, err := os.Stat(configPath)
	if err != nil {
		return config.Config{}, err
	}

	if fstat.IsDir() {
		return config.ParseConfig(filepath.Join(configPath, "config.yaml"))
	}
	return config.ParseConfig(configPath)
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
