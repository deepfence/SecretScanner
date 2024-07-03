package signature

import (
	// "regexp"
	// "regexp/syntax"
	// "strings"
	"bufio"
	"io"
	"math"
	"regexp"
	"strings"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// Constants representing different parts to be matched
// and constants for matching complex regex patterns
const (
	ExtPart         = "extension"
	FilenamePart    = "filename"
	PathPart        = "path"
	ContentsPart    = "contents"
	LargeRegexType  = "large"
	MaxSecretLength = 1000 // Maximum length of secret to search to find exact position of secrets in large regex patterns
)

// Different map data structures to map to appropriate signatures, DBs etc.
var (
	matchRegexpMap      map[string]*regexp.Regexp
	patternRegexpMap    map[string]*regexp.Regexp
	patternSignatureMap map[string][]core.ConfigSignature
	signatureIDMap      map[int]core.ConfigSignature
	matchSignatureMap   map[string]map[string]core.ConfigSignature
)

// Initialize all the data structures
func init() {
	// log.Infof("Initializing Patterns....")
	patternSignatureMap = make(map[string][]core.ConfigSignature)
	signatureIDMap = make(map[int]core.ConfigSignature)
	matchRegexpMap = make(map[string]*regexp.Regexp)
	patternRegexpMap = make(map[string]*regexp.Regexp)
	matchSignatureMap = make(map[string]map[string]core.ConfigSignature)
	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		matchSignatureMap[part] = make(map[string]core.ConfigSignature)
	}
}

// Scan to find complex pattern matches for the contents, path, filename and extension of this file
// @parameters
// contents - content of the file
// path - Complete path of the file
// filename - Name of the file
// extension - Extension of the file
// layerID - layer ID of this file in the container image
// @returns
// []output.SecretFound - List of all secrets found
// Error - Errors if any. Otherwise, returns nil
func MatchPatternSignatures(contents io.ReadSeeker, path string, filename string, extension string, layerID string) ([]output.SecretFound, error) {
	var tempSecretsFound []output.SecretFound
	var matchingStr io.ReadSeeker

	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		if _, has := patternRegexpMap[part]; !has {
			continue
		}

		switch part {
		case FilenamePart:
			matchingStr = strings.NewReader(filename)
		case PathPart:
			matchingStr = strings.NewReader(path)
		case ExtPart:
			matchingStr = strings.NewReader(extension)
		case ContentsPart:
			matchingStr = contents
		}

		indexes := patternRegexpMap[part].FindReaderSubmatchIndex(bufio.NewReaderSize(matchingStr, 2048))
		if indexes != nil {
			match := make([]byte, indexes[1]-indexes[0])
			matchingStr.Seek(int64(indexes[0]), io.SeekStart)
			_, err := matchingStr.Read(match)
			if err != nil {
				logrus.Infof("content read: %v", err)
			}
			matchStr := string(match)

			for _, signature := range patternSignatureMap[part] {
				if signature.CompiledRegex.Match(match) {
					tempSecretsFound = append(tempSecretsFound, output.SecretFound{
						LayerID:          layerID,
						RuleID:           signature.ID,
						RuleName:         signature.Name,
						PartToMatch:      part,
						Match:            matchStr,
						MatchedContents:  matchStr,
						Regex:            signature.Regex,
						Severity:         signature.Severity,
						SeverityScore:    signature.SeverityScore,
						MatchFromByte:    indexes[0],
						MatchToByte:      indexes[1],
						CompleteFilename: path,
					})
					break
				}
			}
		}
	}

	return tempSecretsFound, nil
}

func MatchSimpleSignatures(contents io.ReadSeeker, path string, filename string, extension string, layerID string) ([]output.SecretFound, error) {
	var tempSecretsFound []output.SecretFound
	var matchingStr io.ReadSeeker

	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		if _, has := matchRegexpMap[part]; !has {
			continue
		}

		switch part {
		case FilenamePart:
			matchingStr = strings.NewReader(filename)
		case PathPart:
			matchingStr = strings.NewReader(path)
		case ExtPart:
			matchingStr = strings.NewReader(extension)
		case ContentsPart:
			matchingStr = contents
		}

		indexes := matchRegexpMap[part].FindReaderSubmatchIndex(bufio.NewReaderSize(matchingStr, 2048))
		if indexes != nil {
			match := make([]byte, indexes[1]-indexes[0])
			matchingStr.Seek(int64(indexes[0]), io.SeekStart)
			_, err := matchingStr.Read(match)
			if err != nil {
				logrus.Infof("content read: %v", err)
			}
			matchStr := string(match)
			signature := matchSignatureMap[part][matchStr]

			tempSecretsFound = append(tempSecretsFound, output.SecretFound{
				LayerID:          layerID,
				RuleID:           signature.ID,
				RuleName:         signature.Name,
				PartToMatch:      part,
				Match:            matchStr,
				MatchedContents:  matchStr,
				Regex:            signature.Regex,
				Severity:         signature.Severity,
				SeverityScore:    signature.SeverityScore,
				MatchFromByte:    indexes[0],
				MatchToByte:      indexes[1],
				CompleteFilename: path,
			})
		}
	}

	return tempSecretsFound, nil
}

// Process all the extracted signatures from config file, add severity and severity scores, finally
// store them in appropriate maps
// @parameters
// configSignatures - Extracted patterns from signature config file
func ProcessSignatures(configSignatures []core.ConfigSignature) {
	var simpleContentSignatures []string
	var simpleExtSignatures []string
	var simpleFilenameSignatures []string
	var simplePathSignatures []string

	var patternContentReg []string
	var patternExtReg []string
	var patternFilenameReg []string
	var patternPathReg []string

	var patternContentSignatures []core.ConfigSignature
	var patternExtSignatures []core.ConfigSignature
	var patternFilenameSignatures []core.ConfigSignature
	var patternPathSignatures []core.ConfigSignature

	for i, signature := range configSignatures {
		signature.ID = i

		if signature.Match != "" {
			if signature.Severity == "" {
				signature.Severity = "low"
				signature.SeverityScore = 2.5
			}

			log.Debugf("Simple Signature %s %s %s %s %d", signature.Name,
				signature.Part, signature.Match, signature.Severity, signature.ID)

			matchSignatureMap[signature.Part][signature.Match] = signature

			switch signature.Part {
			case ContentsPart:
				simpleContentSignatures = append(simpleContentSignatures,
					strings.ReplaceAll(signature.Match, ".", `\.`))
			case ExtPart:
				simpleExtSignatures = append(simpleExtSignatures,
					strings.ReplaceAll(signature.Match, ".", `\.`))
			case FilenamePart:
				simpleFilenameSignatures = append(simpleFilenameSignatures,
					strings.ReplaceAll(signature.Match, ".", `\.`))
			case PathPart:
				simplePathSignatures = append(simplePathSignatures,
					strings.ReplaceAll(signature.Match, ".", `\.`))
			}
		} else {
			if signature.Severity == "" {
				if signature.RegexType == LargeRegexType {
					signature.Severity = "high"
					signature.SeverityScore = 7.5
				} else {
					signature.Severity = "medium"
					signature.SeverityScore = 5.0
				}
			}

			log.Debugf("Pattern Signature %s %s %s %s %s %s %d", signature.Name, signature.Part,
				signature.Match, signature.Regex, signature.RegexType, signature.Severity, signature.ID)

			signature.CompiledRegex = regexp.MustCompile(signature.Regex)

			switch signature.Part {
			case ContentsPart:
				patternContentSignatures = append(patternContentSignatures, signature)
				patternContentReg = append(patternContentReg, signature.Regex)
			case ExtPart:
				patternExtSignatures = append(patternExtSignatures, signature)
				patternExtReg = append(patternExtReg, signature.Regex)
			case FilenamePart:
				patternFilenameSignatures = append(patternFilenameSignatures, signature)
				patternFilenameReg = append(patternFilenameReg, signature.Regex)
			case PathPart:
				patternPathSignatures = append(patternPathSignatures, signature)
				patternPathReg = append(patternPathReg, signature.Regex)
			}
		}

		signatureIDMap[signature.ID] = signature

	}

	if len(simpleContentSignatures) != 0 {
		matchRegexpMap[ContentsPart] = regexp.MustCompile(strings.Join(simpleContentSignatures, "|"))
	}
	if len(simpleExtSignatures) != 0 {
		matchRegexpMap[ExtPart] = regexp.MustCompile(strings.Join(simpleExtSignatures, "|"))
	}
	if len(simpleFilenameSignatures) != 0 {
		matchRegexpMap[FilenamePart] = regexp.MustCompile(strings.Join(simpleFilenameSignatures, "|"))
	}
	if len(simplePathSignatures) != 0 {
		matchRegexpMap[PathPart] = regexp.MustCompile(strings.Join(simplePathSignatures, "|"))
	}

	if len(patternContentReg) != 0 {
		patternRegexpMap[ContentsPart] = regexp.MustCompile(strings.Join(patternContentReg, "|"))
	}
	if len(patternExtReg) != 0 {
		patternRegexpMap[ExtPart] = regexp.MustCompile(strings.Join(patternExtReg, "|"))
	}
	if len(patternFilenameReg) != 0 {
		patternRegexpMap[FilenamePart] = regexp.MustCompile(strings.Join(patternFilenameReg, "|"))
	}
	if len(patternPathReg) != 0 {
		patternRegexpMap[PathPart] = regexp.MustCompile(strings.Join(patternPathReg, "|"))
	}

	patternSignatureMap[ContentsPart] = patternContentSignatures
	patternSignatureMap[ExtPart] = patternExtSignatures
	patternSignatureMap[FilenamePart] = patternFilenameSignatures
	patternSignatureMap[PathPart] = patternPathSignatures

	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		log.Debugf("Number of Complex Patterns for matching %s: %d", part, len(patternSignatureMap[part]))
		log.Debugf("Number of Simple Patterns for matching %s: %d", part, len(matchSignatureMap[part]))
	}
}

// Append one signature to the list of signatures
// @parameters
// signature - signature to be added
// configSignatures - List of signatures
func addToSignatures(signature core.ConfigSignature, Signatures *[]core.ConfigSignature) {
	*Signatures = append(*Signatures, signature)
}

// Update severity and score based on length of match
// @parameters
// inputMatch - Matched portion of the input
// severity - Original Severity
// severityScore - Original Severity Score
// @returns
// string - Updated Severity
// float64 - Updated Severity Score
func calculateSeverity(inputMatch []byte, severity string, severityScore float64) (string, float64) {
	updatedSeverity := "low"
	lenMatch := len(inputMatch)
	MinSecretLength := 10

	if lenMatch < MinSecretLength {
		return severity, severityScore
	}

	if lenMatch >= MaxSecretLength {
		return "high", 10.0
	}

	scoreRange := 10.0 - severityScore

	increament := ((float64(lenMatch) - float64(MinSecretLength)) * scoreRange) / (float64(MaxSecretLength) - float64(MinSecretLength))

	updatedScore := severityScore + increament
	if updatedScore > 10.0 {
		updatedScore = 10.0
	}

	if 2.5 < updatedScore && updatedScore <= 7.5 {
		updatedSeverity = "medium"
	} else if 7.5 < updatedScore {
		updatedSeverity = "high"
	}

	return updatedSeverity, math.Round(updatedScore*100) / 100
}

// Find min of 2 int values
func Min(value_0, value_1 int) int {
	if value_0 < value_1 {
		return value_0
	}
	return value_1
}

// Find max of 2 int values
func Max(value_0, value_1 int) int {
	if value_0 > value_1 {
		return value_0
	}
	return value_1
}
