package signature

import (
	// "regexp"
	// "regexp/syntax"
	// "strings"
	"bytes"
	"fmt"
	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/fatih/color"
	"github.com/flier/gohs/hyperscan"
	"regexp"
	"math"
	"errors"
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

// Data structure for passing inputs and getting outputs for hyperscan
type HsInputOutputData struct {
	inputData           []byte
	// Avoids extra memory during blacklist comparison, reduces memory pressure
	inputDataLowerCase  []byte
	completeFilename    string
	layerID             string
	secretsFound        *[]output.SecretFound
	numSecrets          *uint
}

// Different map data structures to map to appropriate signatures, DBs etc.
var (
	simpleSignatureMap  map[string][]core.ConfigSignature
	patternSignatureMap map[string][]core.ConfigSignature
	hyperscanBlockDbMap map[string]hyperscan.BlockDatabase
	signatureIDMap      map[int]core.ConfigSignature
	matchedRuleSet      map[uint]uint // Indicates if any rules macthed in the last iteration
)

// Initialize all the data structures
func init() {
	// core.GetSession().Log.Info("Initializing Patterns....")
	simpleSignatureMap = make(map[string][]core.ConfigSignature)
	patternSignatureMap = make(map[string][]core.ConfigSignature)
	hyperscanBlockDbMap = make(map[string]hyperscan.BlockDatabase)
	signatureIDMap = make(map[int]core.ConfigSignature)
	matchedRuleSet = make(map[uint]uint) // New empty set
}

// Scan to find simple pattern matches for the path, filename and extension of this file
// @parameters
// path - Complete path of the file
// filename - Name of the file
// extension - Extension of the file
// layerID - layer ID of this file in the container image
// @returns
// []output.SecretFound - List of all secrets found
func MatchSimpleSignatures(path string, filename string, extension string, layerID string, numSecrets *uint) []output.SecretFound {
	var tempSecretsFound []output.SecretFound
	var matchingPart string
	var matchingStr string

	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		switch part {
		case FilenamePart:
			matchingPart = FilenamePart
			matchingStr = filename
		case PathPart:
			matchingPart = PathPart
			matchingStr = path
		case ExtPart:
			matchingPart = ExtPart
			matchingStr = extension
		}

		secrets := matchString(matchingPart, matchingStr, path, layerID, numSecrets)
		tempSecretsFound = append(tempSecretsFound, secrets...)
	}

	return tempSecretsFound
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
func MatchPatternSignatures(contents []byte, path string, filename string, extension string, layerID string,
								numSecrets *uint) ([]output.SecretFound, error) {
	var tempSecretsFound []output.SecretFound
	var hsIOData HsInputOutputData
	var matchingPart string
	var matchingStr []byte

	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		switch part {
		case FilenamePart:
			matchingPart = part
			matchingStr = []byte(filename)
		case PathPart:
			matchingPart = part
			matchingStr = []byte(path)
		case ExtPart:
			matchingPart = part
			matchingStr = []byte(extension)
		case ContentsPart:
			matchingPart = part
			matchingStr = contents
		}


		// Ignore if string to match is empty, otherwise hyperscan can return errors
		if len(matchingStr) == 0 {
			continue
		}
		
		hsIOData = HsInputOutputData {
			inputData: matchingStr,
			inputDataLowerCase: bytes.ToLower(matchingStr),
			completeFilename: path,
			layerID: layerID,
			secretsFound: &tempSecretsFound,
			numSecrets: numSecrets,
		}
		err := RunHyperscan(hyperscanBlockDbMap[matchingPart], hsIOData)
		if err != nil {
			core.GetSession().Log.Info("part: %s, path: %s, filename: %s, extenstion: %s, layerID: %s",
										part, path, filename, extension, layerID)
			core.GetSession().Log.Warn("MatchPatternSignatures: %s", err)
			return tempSecretsFound, err
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
				signature.Severity = "Low"
				signature.SeverityScore = 2.5
			}

			core.GetSession().Log.Debug("Simple Signature %s %s %s %s %d", signature.Name,
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
					signature.Severity = "High"
					signature.SeverityScore = 7.5
				} else {
					signature.Severity = "Medium"
					signature.SeverityScore = 5.0
				}
			}

			core.GetSession().Log.Debug("Pattern Signature %s %s %s %s %s %s %d", signature.Name, signature.Part,
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
		core.GetSession().Log.Debug("Number of Complex Patterns for matching %s: %d", part, len(patternSignatureMap[part]))
		core.GetSession().Log.Debug("Number of Simple Patterns for matching %s: %d", part, len(simpleSignatureMap[part]))
	}
}

// Append one signature to the list of signatures
// @parameters
// signature - signature to be added
// configSignatures - List of signatures
func addToSignatures(signature core.ConfigSignature, Signatures *[]core.ConfigSignature) {
	*Signatures = append(*Signatures, signature)
}

// Clear the map of matched ruleset before starting next iteration
func ClearMatchedRuleSet() {
	for k := range matchedRuleSet { // Loop
		delete(matchedRuleSet, k)
	}
}

// Match simple pattern signatures with path, filename or extension
// @parameters
// part - which part to be matched: path, filename or extension
// input - input to be matched
// completeFilename - Complete path of the file
// layerID - layer ID of this file in the container image
// @returns
// []output.SecretFound - List of all secrets found
func matchString(part string, input string, completeFilename string, layerID string,
								numSecrets *uint) []output.SecretFound {
	var tempSecretsFound []output.SecretFound

	for _, signature := range simpleSignatureMap[part] {
		// Don't report secrets if number of secrets exceeds MAX value
		if *numSecrets >= *core.GetSession().Options.MaxSecrets {
			core.GetSession().Log.Debug("MAX secrets exceeded: %d", *numSecrets)
			return tempSecretsFound
		}

		if signature.Match == input {
			if core.ContainsBlacklistedString([]byte(input)) {
				core.GetSession().Log.Debug("matchString: Skipping matches containing blacklisted strings")
				continue
			}
			core.GetSession().Log.Info("Simple Signature %s %s %s %s %s %d\n",signature.Name, signature.Part,
							signature.Match, signature.Regex, signature.Severity, signature.ID)
			core.GetSession().Log.Info("Sensitive file %s found with matching %s of %s\n",
							completeFilename, part, color.RedString(input))

			secret := output.SecretFound{
				LayerID: layerID,
				RuleID:  signature.ID, RuleName: signature.Name,
				PartToMatch: signature.Part, Match: signature.Match, Regex: signature.Regex,
				Severity: signature.Severity, SeverityScore: signature.SeverityScore,
				CompleteFilename: completeFilename,
				MatchFromByte: 0,
				MatchToByte: len(input),
				MatchedContents: input,
			}
			tempSecretsFound = append(tempSecretsFound, secret)
			*numSecrets = *numSecrets + 1
		}
	}

	return tempSecretsFound
}

// Post process after hyperscan finds signature match
// For large pattern matches, find the start of the match (SOM) before printing
// @parameters
// id - ID of matched rule
// from - Start index of the match 
// to - End endex of the match
// flags - This is provided by hyperscan for future use and is unused at present.
// context - Metadata containing contents being matched, filename, layerID etc.
// @returns
// error - Errors if any. Otherwise, returns nil
func processHsRegexMatch(id uint, from, to uint64, flags uint, context interface{}) error {
	var start int
	hsIOData := context.(HsInputOutputData)
	secrets := hsIOData.secretsFound

	// Don't report secrets if number of secrets exceeds MAX value
	if *hsIOData.numSecrets >= *core.GetSession().Options.MaxSecrets {
		core.GetSession().Log.Debug("MAX secrets exceeded: %d", *hsIOData.numSecrets)
		return nil
	}

	sid := int(id)
	start = int(from)
	if signatureIDMap[sid].RegexType == LargeRegexType {
		// Post process to find start of matching for large patterns
		start = getStartOfLargeRegexMatch(sid, int(from), int(to), hsIOData)
	}

	ito := int(to)
	core.GetSession().Log.Debug("processHsRegexMatch: %d %d %d\n", start, ito, len(hsIOData.inputData))
	if core.ContainsBlacklistedString(hsIOData.inputDataLowerCase[start:ito]) {
		core.GetSession().Log.Debug("processHsRegexMatch: Skipping matches containing blacklisted strings")
		return nil
	}

	// Match only once for now, later report only supersets
	// Report multiple matches, only if MultipleMatch is set to true
	_, exists := matchedRuleSet[id] // Check, if this pattern matched for this file earlier
	if !exists {
		matchedRuleSet[id] = 1 // Add to matched rules for first match
	} else if *core.GetSession().Options.MultipleMatch == false {
		return nil // Don't output later matches of this pattern, if multi-match is false
	} else if *core.GetSession().Options.MultipleMatch == true {
		matchedRuleSet[id] = matchedRuleSet[id] + 1
		if matchedRuleSet[id] > *core.GetSession().Options.MaxMultiMatch {
			return nil // Don't output later matches of this pattern, if #Mateches > MaxThreshold
		}
	}

	secret,err := printMatchedSignatures(sid, start, int(to), hsIOData)
	if err != nil {
		core.GetSession().Log.Error("processHsRegexMatch: %s", err)
		return nil
	}
	*secrets = append(*secrets, secret)
	*hsIOData.numSecrets = *hsIOData.numSecrets + 1

	return nil
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
	core.GetSession().Log.Debug("Number of matches found for large regex pattern: %d", len(allMatchedIndexes))
	for i, loc := range allMatchedIndexes {
		// Currently just print the last match as we know the end of the hyperscan match
		if i == len(allMatchedIndexes)-1 {
			// secret := printMatchedSignatures(sid, start+loc[0], start+loc[1], hsIOData)
			// *secrets = append(*secrets, secret)
			return start+loc[0]
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

	core.GetSession().Log.Info("Pattern Signature %s %s %s %s %s %s %.2f %d", signatureIDMap[sid].Name, signatureIDMap[sid].Part,
						signatureIDMap[sid].Match, signatureIDMap[sid].Regex, signatureIDMap[sid].RegexType,
						updatedSeverity, updatedScore, signatureIDMap[sid].ID)
	// fmt.Println(signatureIDMap[sid].Name, signatureIDMap[sid].Part, signatureIDMap[sid].Match, signatureIDMap[sid].Regex,
	//	signatureIDMap[sid].RegexType, updatedSeverity, updatedScore, signatureIDMap[sid].ID)
	core.GetSession().Log.Info("Secret found in %s of %s within bytes %d and %d", signatureIDMap[sid].Part, completeFilename, from, to)
	// fmt.Println("Secret found in", signatureIDMap[sid].Part, "of", completeFilename, "withing bytes", from, "and", to)

	start := Max(0, bytes.LastIndexByte(inputData[:from], '\n')) // Avoid -ve value from IndexByte
	end := to + Max(0, bytes.IndexByte(inputData[to:], '\n'))    // Avoid -ve value from IndexByte

	// Display max 50 bytes before and after the maching string
	start = Max(start, from-50)
	end = Min(end, to+50)

	if !(0 <= start && start <= from && from <= to && to <=end && end <= len(inputData)) {
		return output.SecretFound{}, errors.New("index out of bound while printing matched signatures")
	}

	coloredMatch := fmt.Sprintf("%s%s%s\n", inputData[start:from], color.RedString(string(inputData[from:to])), inputData[to:end])
	//core.GetSession().Log.Info("%s%s%s\n", inputData[start:from], color.RedString(string(inputData[from:to])), inputData[to:end])
	core.GetSession().Log.Info(coloredMatch)
	
	secret := output.SecretFound{
		LayerID: layerID,
		RuleID:  sid, RuleName: signatureIDMap[sid].Name,
		PartToMatch: signatureIDMap[sid].Part, Match: signatureIDMap[sid].Match, Regex: signatureIDMap[sid].Regex,
		Severity: updatedSeverity, SeverityScore: updatedScore,
		CompleteFilename: completeFilename,
		PrintBufferStartIndex: start, MatchFromByte:    from-start, MatchToByte: to-start,
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

	increament := (((float64(lenMatch) - float64(MinSecretLength)))*scoreRange)/(float64(MaxSecretLength)-float64(MinSecretLength))

	updatedScore := severityScore + increament
	if updatedScore > 10.0 {
		updatedScore = 10.0
	}

	if 2.5 < updatedScore && updatedScore <= 7.5 {
		updatedSeverity = "Medium"
	} else if 7.5 < updatedScore {
		updatedSeverity = "high"
	}

	return updatedSeverity, math.Round(updatedScore*100)/100
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
