package core_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/deepfence/SecretScanner/core"
)

func Test_ConfigMerge(t *testing.T) {
	config := &core.Config{
		BlacklistedStrings:           []string{"base"},
		BlacklistedExtensions:        []string{"base"},
		BlacklistedPaths:             []string{"base"},
		BlacklistedEntropyExtensions: []string{"base"},
		Signatures: []core.ConfigSignature{
			{
				Name:          "base",
				Part:          "base",
				Match:         "base",
				Regex:         "base",
				RegexType:     "base",
				Verifier:      "base",
				Severity:      "base",
				SeverityScore: 100,
				ID:            0,
			},
			{
				Name:          "overwrite",
				Part:          "base",
				Match:         "base",
				Regex:         "base",
				RegexType:     "base",
				Verifier:      "base",
				Severity:      "base",
				SeverityScore: 100,
				ID:            1,
			},
		},
	}

	config.Merge(&core.Config{
		BlacklistedStrings:           []string{"merge"},
		BlacklistedExtensions:        []string{"merge", "base"},
		BlacklistedPaths:             []string{"base", "merge"},
		BlacklistedEntropyExtensions: []string{"base"},
		Signatures: []core.ConfigSignature{
			{
				Name:          "merge",
				Part:          "merge",
				Match:         "merge",
				Regex:         "merge",
				RegexType:     "merge",
				Verifier:      "merge",
				Severity:      "merge",
				SeverityScore: 200,
				ID:            2,
			},
			{
				Name:          "overwrite",
				Part:          "merge",
				Match:         "merge",
				Regex:         "merge",
				RegexType:     "merge",
				Verifier:      "merge",
				Severity:      "merge",
				SeverityScore: 200,
				ID:            3,
			},
		},
	})

	expected := &core.Config{
		BlacklistedStrings:           []string{"base", "merge"},
		BlacklistedExtensions:        []string{"base", "merge"},
		BlacklistedPaths:             []string{"base", "merge"},
		BlacklistedEntropyExtensions: []string{"base"},
		Signatures: []core.ConfigSignature{
			{
				Name:          "base",
				Part:          "base",
				Match:         "base",
				Regex:         "base",
				RegexType:     "base",
				Verifier:      "base",
				Severity:      "base",
				SeverityScore: 100,
				ID:            0,
			},
			{
				Name:          "overwrite",
				Part:          "merge",
				Match:         "merge",
				Regex:         "merge",
				RegexType:     "merge",
				Verifier:      "merge",
				Severity:      "merge",
				SeverityScore: 200,
				ID:            3,
			},
			{
				Name:          "merge",
				Part:          "merge",
				Match:         "merge",
				Regex:         "merge",
				RegexType:     "merge",
				Verifier:      "merge",
				Severity:      "merge",
				SeverityScore: 200,
				ID:            2,
			},
		},
	}

	if !reflect.DeepEqual(config, expected) {
		t.Errorf("merge does not match expected\nActual:\n%v\nExpected:\n%v", mustMarshal(config), mustMarshal(expected))
	}

}

func mustMarshal(in interface{}) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	err := enc.Encode(in)
	if err != nil {
		panic(err)
	}
	return buf.String()
}
