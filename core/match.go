package core

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

type MatchFile struct {
	Path      string
	Filename  string
	Extension string
	Contents  []byte
}

// NewMatchFile Creates a new Matchfile data structure
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

// IsSkippableFile Checks if the path is blacklisted
func IsSkippableDir(path string, baseDir string) bool {
	hostMountPath := *session.Options.HostMountPath
	if hostMountPath != "" {
		baseDir = hostMountPath
	}

	for _, skippablePathIndicator := range session.Config.BlacklistedPaths {
		if strings.Contains(path, baseDir+skippablePathIndicator) {
			return true
		}
	}

	return false
}

// IsSkippableFileExtension Checks if the file extension is blacklisted
func IsSkippableFileExtension(path string) bool {
	extension := strings.ToLower(filepath.Ext(path))
	for _, skippableExt := range session.Config.BlacklistedExtensions {
		if extension == skippableExt {
			return true
		}
	}
	return false
}

// CanCheckEntropy Checks if entropy based scanning is appropriate for this file
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

// ContainsBlacklistedString Checks if the input contains a blacklisted string
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

//// GetMatchingFiles Return the list of all applicable files inside the given directory for scanning
//func GetMatchingFiles(dir string, baseDir string) (*bytes.Buffer, *bytes.Buffer, error) {
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
//	GetSession().Log.Info("find command: %s", findCmd)
//
//	return ExecuteCommand(findCmd)
//}

// UpdateDirsPermissionsRW Update permissions for dirs in container images, so that they can be properly deleted
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
