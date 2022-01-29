package signature

import (
	"fmt"
	"github.com/deepfence/SecretScanner/core"
	"github.com/flier/gohs/hyperscan"
	"os"
)

// Build hyperscan Databases for matching different parts in the beginning
// This can be used for repeated scanning
func BuildHsDb() {
	for _, part := range []string{ContentsPart, FilenamePart, PathPart, ExtPart} {
		core.GetSession().Log.Info("Creating hyperscan database for %s", part)
		hspatterns, err := CreateHsPatterns(part)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to create patterns \"%s\": %s\n", err.Error())
			os.Exit(1)
		}
		hyperscanBlockDbMap[part] = CreateHsDb(hspatterns)
	}
}

// Create a list of hyperscan patterns with appropriate flags
// @parameters
// part - part for which list of patterns to be created: content, path, filename or extension
// @returns
// []*hyperscan.Pattern - List of hyperscan patterns
// error - Errors if any. Otherwise, returns nil
func CreateHsPatterns(part string) ([]*hyperscan.Pattern, error) {
	var hsPatterns []*hyperscan.Pattern

	core.GetSession().Log.Debug("Number of Complex Patterns for matching %s: %d", part, len(patternSignatureMap[part]))
	for _, signature := range patternSignatureMap[part] {
		core.GetSession().Log.Debug("Pattern Signature %s %s %s %s %s %s %d", signature.Name, signature.Part, signature.Match, signature.Regex, signature.RegexType, signature.Severity, signature.ID)

		// Disable SomLeftMost option for large regex to avoid HS compilation failures.
		// Postprocess later to find patterns
		hsPattern := hyperscan.NewPattern(signature.Regex, hyperscan.DotAll|hyperscan.SomLeftMost) // hyperscan.SingleMatch
		if signature.RegexType == LargeRegexType {
			hsPattern = hyperscan.NewPattern(signature.Regex, hyperscan.DotAll)
			if *core.GetSession().Options.MultipleMatch == false {
				hsPattern = hyperscan.NewPattern(signature.Regex, hyperscan.DotAll|hyperscan.SingleMatch)
			} else {
				hsPattern = hyperscan.NewPattern(signature.Regex, hyperscan.DotAll)
			}
		}
		hsPattern.Id = signature.ID
		hsPatterns = append(hsPatterns, hsPattern)
	}
	return hsPatterns, nil
}

// Create Hyperscan databased, which can be used for repeated scanning
// @parameters
// hsPatterns -  List of hyperscan patterns
// @returns
// BlockDatabase - Hyperscan database for the given list of patterns
func CreateHsDb(hsPatterns []*hyperscan.Pattern) hyperscan.BlockDatabase {
	hyperscanBlockDb, err := hyperscan.NewBlockDatabase(hsPatterns...)
	if err != nil {
		fmt.Println("ERROR: Unable to compile pattern", err.Error())
		os.Exit(1)
	}
	return hyperscanBlockDb
}

// Run hyperscan matching on the specified content
// @parameters
// hyperscanBlockDb - Hyperscan database of a list of patterns
// hsIOData - Metadata containing the contents being matched, filename, layerID etc.
// @returns
// Error - Errors if any. Otherwise, returns nil
func RunHyperscan(hyperscanBlockDb hyperscan.BlockDatabase, hsIOData HsInputOutputData) error {
	hyperscanScratch, err := hyperscan.NewScratch(hyperscanBlockDb)
	if err != nil {
		return err
	}
	defer hyperscanScratch.Free()

	metadata := hsIOData
	if err := hyperscanBlockDb.Scan([]byte(metadata.inputData), hyperscanScratch, hyperscanEventHandler, metadata); err != nil {
		core.GetSession().Log.Info("First 100 bytes of inputData: %s", metadata.inputData[:Min(len(metadata.inputData), 100)])
		core.GetSession().Log.Warn("RunHyperscan: %s", err)
		return err
	}
	return nil
}

// This is the function that will be called by hyperscan for each match that occurs.
// @parameters
// id - ID of matched rule
// from - Start index of the match
// to - End endex of the match
// flags - This is provided by hyperscan for future use and is unused at present.
// context - Metadata containing the contents being matched, filename, layerID etc.
// @returns
// error - Errors if any. Otherwise, returns nil
func hyperscanEventHandler(id uint, from, to uint64, flags uint, context interface{}) error {
	err := processHsRegexMatch(id, from, to, flags, context)
	return err
}
