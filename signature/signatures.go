package signature

import (
	// "regexp"
	// "regexp/syntax"
	// "strings"
	"bufio"
	"bytes"
	"errors"
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

type HsInputOutputData struct {
	inputData []byte
	// Avoids extra memory during blacklist comparison, reduces memory pressure
	inputDataLowerCase []byte
	completeFilename   string
	layerID            string
	secretsFound       *[]output.SecretFound
	numSecrets         *uint
	matchedRuleSet     map[uint]uint // Indicates if any rules macthed in the last iteration
}

// Different map data structures to map to appropriate signatures, DBs etc.
var (
	simpleSignatureMap  map[string][]core.ConfigSignature
	patternSignatureMap map[string][]core.ConfigSignature
	signatureIDMap      map[int]core.ConfigSignature
)

// Initialize all the data structures
func init() {
	// log.Infof("Initializing Patterns....")
	simpleSignatureMap = make(map[string][]core.ConfigSignature)
	patternSignatureMap = make(map[string][]core.ConfigSignature)
	signatureIDMap = make(map[int]core.ConfigSignature)
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
func MatchPatternSignatures(contents io.ReadSeeker, path string, filename string, extension string, layerID string,
	numSecrets *uint, matchedRuleSet map[uint]uint) ([]output.SecretFound, error) {
	var tempSecretsFound []output.SecretFound
	//var hsIOData HsInputOutputData
	var matchingPart string
	var matchingStr io.RuneReader

	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		switch part {
		case FilenamePart:
			matchingPart = part
			matchingStr = bufio.NewReader(strings.NewReader(filename))
		case PathPart:
			matchingPart = part
			matchingStr = bufio.NewReader(strings.NewReader(path))
		case ExtPart:
			matchingPart = part
			matchingStr = bufio.NewReader(strings.NewReader(extension))
		case ContentsPart:
			matchingPart = part
			matchingStr = bufio.NewReader(contents)
		}

		//hsIOData = HsInputOutputData{
		//	inputData:          matchingStr,
		//	inputDataLowerCase: bytes.ToLower(matchingStr),
		//	completeFilename:   path,
		//	layerID:            layerID,
		//	secretsFound:       &tempSecretsFound,
		//	numSecrets:         numSecrets,
		//	matchedRuleSet:     matchedRuleSet,
		//}
		for _, regex := range patternSignatureMap[matchingPart] {
			indexes := regex.CompiledRegex.FindReaderSubmatchIndex(matchingStr)
			if indexes != nil {
				match := make([]byte, indexes[1]-indexes[0])
				contents.Seek(int64(indexes[0]), io.SeekStart)
				_, err := contents.Read(match)
				if err != nil {
					logrus.Infof("content read: %v", err)
				}

				tempSecretsFound = append(tempSecretsFound, output.SecretFound{
					LayerID:          layerID,
					RuleID:           regex.ID,
					RuleName:         regex.Name,
					PartToMatch:      part,
					Match:            string(match),
					Regex:            regex.Regex,
					Severity:         regex.Severity,
					SeverityScore:    regex.SeverityScore,
					MatchFromByte:    indexes[0],
					MatchToByte:      indexes[1],
					CompleteFilename: filename,
				})
				break
			}
		}
	}

	return tempSecretsFound, nil
}

// Process all the extracted signatures from config file, add severity and severity scores, finally
// store them in appropriate maps
// @parameters
// configSignatures - Extracted patterns from signature config file
func ProcessSignatures(configSignatures []core.ConfigSignature) {
	var simpleContentSignatures []core.ConfigSignature
	var simpleExtSignatures []core.ConfigSignature
	var simpleFilenameSignatures []core.ConfigSignature
	var simplePathSignatures []core.ConfigSignature

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

			switch signature.Part {
			case ContentsPart:
				addToSignatures(signature, &simpleContentSignatures)
			case ExtPart:
				addToSignatures(signature, &simpleExtSignatures)
			case FilenamePart:
				addToSignatures(signature, &simpleFilenameSignatures)
			case PathPart:
				addToSignatures(signature, &simplePathSignatures)
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

	simpleSignatureMap[ContentsPart] = simpleContentSignatures
	simpleSignatureMap[ExtPart] = simpleExtSignatures
	simpleSignatureMap[FilenamePart] = simpleFilenameSignatures
	simpleSignatureMap[PathPart] = simplePathSignatures

	patternSignatureMap[ContentsPart] = patternContentSignatures
	patternSignatureMap[ExtPart] = patternExtSignatures
	patternSignatureMap[FilenamePart] = patternFilenameSignatures
	patternSignatureMap[PathPart] = patternPathSignatures

	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		log.Debugf("Number of Complex Patterns for matching %s: %d", part, len(patternSignatureMap[part]))
		log.Debugf("Number of Simple Patterns for matching %s: %d", part, len(simpleSignatureMap[part]))
	}
}

// Append one signature to the list of signatures
// @parameters
// signature - signature to be added
// configSignatures - List of signatures
func addToSignatures(signature core.ConfigSignature, Signatures *[]core.ConfigSignature) {
	*Signatures = append(*Signatures, signature)
}

// For large regex patterns, if Hyperscan finds a match, then
// find the matching indexes directly as start of match (SOM) hyperscan flag doesn't work
// for large patterns.
// @parameters
// sid - ID of matched rule
// from - Start index of the match
// to - End endex of the match
// hsIOData - Metadata containing contents being matched, filename, layerID etc.
// @returns
// int - Exact start index of the large complex regex matches
func getStartOfLargeRegexMatch(sid int, from, to int, hsIOData HsInputOutputData) int {
	inputData := hsIOData.inputData
	// secrets := hsIOData.secretsFound

	pattern := signatureIDMap[sid].CompiledRegex
	// Hyperscan doesn't give the start of the match, but it give the end of the match for complex patterns
	start := Max(0, to-MaxSecretLength)
	// Search between [to-MaxSecretLength, to] to find exact match of secret
	end := to
	allMatchedIndexes := pattern.FindAllIndex(inputData[start:end], -1)
	log.Debugf("Number of matches found for large regex pattern: %d", len(allMatchedIndexes))
	for i, loc := range allMatchedIndexes {
		// Currently just print the last match as we know the end of the hyperscan match
		if i == len(allMatchedIndexes)-1 {
			// secret := printMatchedSignatures(sid, start+loc[0], start+loc[1], hsIOData)
			// *secrets = append(*secrets, secret)
			return start + loc[0]
		}
	}

	// It shouldn't reach here. Return "from" as start index, by default
	return from
}

// Print matched secrets on standard output as well as in output files in json format etc.
// @parameters
// sid - ID of matched rule
// from - Start index of the match
// to - End endex of the match
// hsIOData - Metadata containing contents being matched, filename, layerID etc.
// @returns
// output.SecretFound - secret found
// Error - Errors if any. Otherwise, returns nil
func printMatchedSignatures(sid int, from, to int, hsIOData HsInputOutputData) (output.SecretFound, error) {
	inputData := hsIOData.inputData
	completeFilename := hsIOData.completeFilename
	layerID := hsIOData.layerID

	updatedSeverity, updatedScore := calculateSeverity(inputData[from:to], signatureIDMap[sid].Severity, signatureIDMap[sid].SeverityScore)

	log.Debugf("Pattern Signature %s %s %s %s %s %s %.2f %d", signatureIDMap[sid].Name, signatureIDMap[sid].Part,
		signatureIDMap[sid].Match, signatureIDMap[sid].Regex, signatureIDMap[sid].RegexType,
		updatedSeverity, updatedScore, signatureIDMap[sid].ID)
	// fmt.Println(signatureIDMap[sid].Name, signatureIDMap[sid].Part, signatureIDMap[sid].Match, signatureIDMap[sid].Regex,
	//	signatureIDMap[sid].RegexType, updatedSeverity, updatedScore, signatureIDMap[sid].ID)
	log.Debugf("Secret found in %s of %s within bytes %d and %d", signatureIDMap[sid].Part, completeFilename, from, to)
	// fmt.Println("Secret found in", signatureIDMap[sid].Part, "of", completeFilename, "withing bytes", from, "and", to)

	start := Max(0, bytes.LastIndexByte(inputData[:from], '\n')) // Avoid -ve value from IndexByte
	end := to + Max(0, bytes.IndexByte(inputData[to:], '\n'))    // Avoid -ve value from IndexByte

	// Display max 50 bytes before and after the maching string
	start = Max(start, from-50)
	end = Min(end, to+50)

	if !(0 <= start && start <= from && from <= to && to <= end && end <= len(inputData)) {
		return output.SecretFound{}, errors.New("index out of bound while printing matched signatures")
	}

	// coloredMatch := fmt.Sprintf("%s%s%s\n", inputData[start:from], color.RedString(string(inputData[from:to])), inputData[to:end])
	// //log.Infof("%s%s%s\n", inputData[start:from], color.RedString(string(inputData[from:to])), inputData[to:end])
	// log.Infof(coloredMatch)

	secret := output.SecretFound{
		LayerID: layerID,
		RuleID:  sid, RuleName: signatureIDMap[sid].Name,
		PartToMatch: signatureIDMap[sid].Part, Match: signatureIDMap[sid].Match, Regex: signatureIDMap[sid].Regex,
		Severity: updatedSeverity, SeverityScore: updatedScore,
		CompleteFilename:      completeFilename,
		PrintBufferStartIndex: start, MatchFromByte: from - start, MatchToByte: to - start,
		MatchedContents: string(inputData[start:end]),
	}

	return secret, nil
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

func BuildRegexes() {
	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		log.Debugf("Compile regexp database for %s", part)
		CompileRegexpPatterns(part)
	}
}

func CompileRegexpPatterns(part string) {
	log.Debugf("Number of Complex Patterns for matching %s: %d", part, len(patternSignatureMap[part]))
	for i, signature := range patternSignatureMap[part] {
		log.Debugf("Pattern Signature %s %s %s %s %s %s %d",
			signature.Name, signature.Part, signature.Match,
			signature.Regex, signature.RegexType, signature.Severity,
			signature.ID)

		signature.CompiledRegex = regexp.MustCompile(signature.Regex)
		patternSignatureMap[part][i] = signature
	}
}
