package core

import (
	"os"
	"path/filepath"
	"strings"
	"bytes"
)

type MatchFile struct {
	Path      string
	Filename  string
	Extension string
	Contents  []byte
}

// Creates a new Matchfile data structure
func NewMatchFile(path string) MatchFile {
	path = filepath.ToSlash(path)
	_, filename := filepath.Split(path)
	extension := filepath.Ext(path)
	// contents, _ := ioutil.ReadFile(path)

	return MatchFile{
		Path:      path,
		Filename:  filename,
		Extension: extension,
		Contents:  []byte(""), // contents,
	}
}

// Checks if the path is blacklisted
func IsSkippableFile(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))

	for _, skippableExt := range session.Config.BlacklistedExtensions {
		if extension == skippableExt {
			return true
		}
	}

	for _, skippablePathIndicator := range session.Config.BlacklistedPaths {
		skippablePathIndicator = strings.Replace(skippablePathIndicator, "{sep}", string(os.PathSeparator), -1)
		if strings.Contains(path, skippablePathIndicator) {
			return true
		}
	}

	return false
}

// Checks if entropy based scanning is appropriate for this file
func (match MatchFile) CanCheckEntropy() bool {
	if match.Filename == "id_rsa" {
		return false
	}

	for _, skippableExt := range session.Config.BlacklistedEntropyExtensions {
		if match.Extension == skippableExt {
			return false
		}
	}

	return true
}

// Checks if the input contains a blacklisted string
func ContainsBlacklistedString(input []byte) bool {
	for _, blacklistedString := range session.Config.BlacklistedStrings {
		blacklistedByteStr := []byte(blacklistedString)
		if bytes.Contains(input, blacklistedByteStr) {
			GetSession().Log.Debug("Blacklisted string %s matched", blacklistedString)
			return true
		}
	}
		
	return false
}

// Return the list of all applicable files inside the given directory for scanning
func GetMatchingFiles(dir string) []MatchFile {
	fileList := make([]MatchFile, 0)
	maxFileSize := *session.Options.MaximumFileSize * 1024

	filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if err != nil || f.IsDir() || uint(f.Size()) > maxFileSize || IsSkippableFile(path) {
			return nil
		}
		fileList = append(fileList, NewMatchFile(path))
		return nil
	})

	return fileList
}

// Update permissions for dirs in container images, so that they can be properly deleted
func UpdateDirsPermissionsRW(dir string) {
	filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if f.IsDir() {
			err := os.Chmod(path, 0700)
			if err != nil {
				GetSession().Log.Error("Failed to change dir %s permission: %s", path, err)
			}
		}
		return nil
	})
}
