package signature

import (
	"bufio"
	"io"
	"math"
	"regexp"
	"strings"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/rs/zerolog/log"
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
	patternSignatureMap map[string][]core.ConfigSignature
	signatureIDMap      map[int]core.ConfigSignature
	matchSignatureMap   map[string]map[string]core.ConfigSignature
)

// Initialize all the data structures
func init() {
	patternSignatureMap = make(map[string][]core.ConfigSignature)
	signatureIDMap = make(map[int]core.ConfigSignature)
	matchRegexpMap = make(map[string]*regexp.Regexp)
	matchSignatureMap = make(map[string]map[string]core.ConfigSignature)
	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		matchSignatureMap[part] = make(map[string]core.ConfigSignature)
	}
}

// MatchPatternSignatures Scan to find complex pattern matches for the contents, path, filename and extension of this file
func MatchPatternSignatures(contents io.ReadSeeker, path string, filename string, extension string, layerID string) ([]output.SecretFound, error) {
	var tempSecretsFound []output.SecretFound
	var matchingStr io.ReadSeeker

	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {

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

		for _, signature := range patternSignatureMap[part] {
			matchingStr.Seek(0, io.SeekStart)
			indexes := signature.CompiledRegex.FindReaderIndex(bufio.NewReader(matchingStr))
			if indexes != nil {
				match := make([]byte, indexes[1]-indexes[0])
				matchingStr.Seek(int64(indexes[0]), io.SeekStart)
				_, err := matchingStr.Read(match)
				if err != nil {
					log.Info().Err(err).Msg("content read error")
				}
				matchStr := string(match)
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

		indexes := matchRegexpMap[part].FindReaderIndex(bufio.NewReader(matchingStr))
		if indexes != nil {
			match := make([]byte, indexes[1]-indexes[0])
			matchingStr.Seek(int64(indexes[0]), io.SeekStart)
			_, err := matchingStr.Read(match)
			if err != nil {
				log.Info().Err(err).Msg("content read error")
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

// ProcessSignatures Process all the extracted signatures from config file, add severity and severity scores, finally
// store them in appropriate maps
func ProcessSignatures(configSignatures []core.ConfigSignature) {
	var simpleContentSignatures []string
	var simpleExtSignatures []string
	var simpleFilenameSignatures []string
	var simplePathSignatures []string

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

			log.Debug().Str("name", signature.Name).Str("part", signature.Part).
				Str("match", signature.Match).Str("severity", signature.Severity).
				Int("id", signature.ID).Msg("Simple Signature")

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

			log.Debug().Str("name", signature.Name).Str("part", signature.Part).
				Str("match", signature.Match).Str("regex", signature.Regex).
				Str("regexType", signature.RegexType).Str("severity", signature.Severity).
				Int("id", signature.ID).Msg("Pattern Signature")

			signature.CompiledRegex = regexp.MustCompile(signature.Regex)

			switch signature.Part {
			case ContentsPart:
				patternContentSignatures = append(patternContentSignatures, signature)
			case ExtPart:
				patternExtSignatures = append(patternExtSignatures, signature)
			case FilenamePart:
				patternFilenameSignatures = append(patternFilenameSignatures, signature)
			case PathPart:
				patternPathSignatures = append(patternPathSignatures, signature)
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

	patternSignatureMap[ContentsPart] = patternContentSignatures
	patternSignatureMap[ExtPart] = patternExtSignatures
	patternSignatureMap[FilenamePart] = patternFilenameSignatures
	patternSignatureMap[PathPart] = patternPathSignatures

	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		log.Debug().Str("part", part).Int("count", len(patternSignatureMap[part])).Msg("Number of Complex Patterns")
		log.Debug().Str("part", part).Int("count", len(matchSignatureMap[part])).Msg("Number of Simple Patterns")
	}
}

// addToSignatures Append one signature to the list of signatures
func addToSignatures(signature core.ConfigSignature, Signatures *[]core.ConfigSignature) {
	*Signatures = append(*Signatures, signature)
}

// calculateSeverity Update severity and score based on length of match
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

// Min Find min of 2 int values
func Min(value_0, value_1 int) int {
	if value_0 < value_1 {
		return value_0
	}
	return value_1
}

// Max Find max of 2 int values
func Max(value_0, value_1 int) int {
	if value_0 > value_1 {
		return value_0
	}
	return value_1
}
