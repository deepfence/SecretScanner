package core

import (
	"crypto/sha1"
	"encoding/hex"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// CreateRecursiveDir Create directory structure recursively, if they do not exist
func CreateRecursiveDir(completePath string) error {
	if _, err := os.Stat(completePath); os.IsNotExist(err) {
		log.Debug().Str("path", completePath).Msg("Folder does not exist. Creating folder...")
		err = os.MkdirAll(completePath, os.ModePerm)
		if err != nil {
			log.Error().Err(err).Str("path", completePath).Msg("createRecursiveDir failed")
		}
		return err
	} else if err != nil {
		log.Error().Err(err).Str("path", completePath).Msg("createRecursiveDir error, deleting temp dir")
		_ = DeleteTmpDir(completePath)
		return err
	}

	return nil
}

// Create a sanitized string from image name which can used as a filename
func getSanitizedString(imageName string) string {
	reg, err := regexp.Compile("[^A-Za-z0-9]+")
	if err != nil {
		return "error"
	}
	sanitizedName := reg.ReplaceAllString(imageName, "")
	return sanitizedName
}

// GetTmpDir Create a temporary directory to extract the contents of container image
func GetTmpDir(imageName string) (string, error) {
	scanID := "df_" + getSanitizedString(imageName)

	dir := *session.Options.TempDirectory
	tempPath := filepath.Join(dir, "Deepfence", TempDirSuffix, scanID)

	completeTempPath := path.Join(tempPath, ExtractedImageFilesDir)

	err := CreateRecursiveDir(completeTempPath)
	if err != nil {
		log.Error().Err(err).Msg("getTmpDir: Could not create temp dir")
		return "", err
	}

	return tempPath, err
}

// DeleteTmpDir Delete the temporary directory
func DeleteTmpDir(outputDir string) error {
	log.Info().Str("dir", outputDir).Msg("Deleting temporary dir")
	if outputDir != "" {
		err := os.RemoveAll(outputDir)
		if err != nil {
			log.Error().Err(err).Msg("deleteTmpDir: Could not delete temp dir")
			return err
		}
	}
	return nil
}

// DeleteFiles Delete all the files and dirs recursively in specified directory
func DeleteFiles(path string, wildCard string) {
	var val string
	files, _ := filepath.Glob(path + wildCard)
	for _, val = range files {
		os.RemoveAll(val)
	}
}

// IsSymLink Check if input is a symLink, not normal file/dir
func IsSymLink(path string) bool {
	fileInfo, err := os.Lstat(path)

	if err != nil {
		return false
	}

	if fileInfo.Mode()&os.ModeSymlink == os.ModeSymlink {
		return true
	}

	return false
}

func PathExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}

	if os.IsNotExist(err) {
		return false
	}

	return false
}

func LogIfError(text string, err error) {
	if err != nil {
		log.Error().Err(err).Msg(text)
	}
}

func GetHash(s string) string {
	h := sha1.New()
	h.Write([]byte(s))

	return hex.EncodeToString(h.Sum(nil))
}

func Pluralize(count int, singular string, plural string) string {
	if count == 1 {
		return singular
	}

	return plural
}

func GetEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	for i := 0; i < 256; i++ {
		px := float64(strings.Count(data, string(byte(i)))) / float64(len(data))
		if px > 0 {
			entropy += -px * math.Log2(px)
		}
	}

	return entropy
}

func GetTimestamp() int64 {
	return time.Now().UTC().UnixNano() / 1000000
}

func GetCurrentTime() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z"
}
