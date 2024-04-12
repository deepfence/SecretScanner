package core

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
)

type MatchFile struct {
	Path      string
	Filename  string
	Extension string
	Contents  []byte
}

// NewMatchFile Creates a new Matchfile data structure
func NewMatchFile(path string) MatchFile {

	extension := filepath.Base(path)
	filename := strings.TrimSuffix(filepath.Base(path), extension)
	// contents, _ := ioutil.ReadFile(path)

	return MatchFile{
		Path:      path,
		Filename:  filename,
		Extension: extension,
		Contents:  []byte(""), // contents,
	}
}

func checkPrefix(baseDir, input string) func(string) bool {
	return func(compareParam string) bool {
		return strings.HasPrefix(input, compareParam) || strings.HasPrefix(input, filepath.Join(baseDir, compareParam))
	}
}

func checkContains(baseDir, input string) func(string) bool {
	return func(compareParam string) bool {
		return strings.Contains(input, compareParam) || strings.Contains(input, filepath.Join(baseDir, compareParam))
	}
}

// IsSkippableFile Checks if the path is blacklisted
func IsSkippableDir(path string, baseDir string) bool {
	hostMountPath := *session.Options.HostMountPath
	if hostMountPath != "" {
		baseDir = hostMountPath
	}
	var retVal = false
	retVal = slices.ContainsFunc(session.Config.BlacklistedPaths, checkPrefix(baseDir, path))
	if retVal {
		return retVal
	}
	retVal = slices.ContainsFunc(session.Config.ExcludePaths, checkContains(baseDir, path))
	return retVal
}

// IsSkippableFileExtension Checks if the file extension is blacklisted
func IsSkippableFileExtension(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	return slices.Contains(session.Config.BlacklistedExtensions, extension)
}

// CanCheckEntropy Checks if entropy based scanning is appropriate for this file
func (match MatchFile) CanCheckEntropy() bool {
	if match.Filename == "id_rsa" {
		return false
	}
	return slices.Contains(session.Config.BlacklistedEntropyExtensions, match.Extension)
}

func byteCompare(input []byte) func(string) bool {
	return func(compareParam string) bool {
		return bytes.Contains(input, []byte(compareParam))
	}
}

// ContainsBlacklistedString Checks if the input contains a blacklisted string
func ContainsBlacklistedString(input []byte) bool {

	return slices.ContainsFunc(session.Config.BlacklistedStrings, byteCompare(input))
}

//// GetMatchingFiles Return the list of all applicable files inside the given directory for scanning
// func GetMatchingFiles(dir string, baseDir string) (*bytes.Buffer, *bytes.Buffer, error) {
//	findCmd := "find " + dir
//	for _, skippableExt := range session.Config.BlacklistedExtensions {
//		findCmd += " -not -name \"*" + skippableExt + "\""
//	}
//	hostMountPath := *session.Options.HostMountPath
//	if hostMountPath != "" {
//		baseDir = hostMountPath
//	}
//	for _, skippablePathIndicator := range session.Config.BlacklistedPaths {
//		findCmd += " -path " + baseDir + skippablePathIndicator + " -prune -o"
//	}
//	maxFileSize := strconv.FormatUint(uint64(*session.Options.MaximumFileSize), 10)
//	findCmd += " -type f -size " + maxFileSize + "M"
//	log.Info("find command: %s", findCmd)
//
//	return ExecuteCommand(findCmd)
//}

// UpdateDirsPermissionsRW Update permissions for dirs in container images, so that they can be properly deleted
func UpdateDirsPermissionsRW(dir string) {
	_ = filepath.WalkDir(dir, func(path string, f os.DirEntry, err error) error {
		if f.IsDir() {
			err := os.Chmod(path, 0700)
			if err != nil {
				log.Errorf("Failed to change dir %s permission: %s", path, err)
			}
		}
		return nil
	})
}
