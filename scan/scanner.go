package scan

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/signature"
	tasks "github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	"github.com/deepfence/match-scanner/pkg/extractor"
	genscan "github.com/deepfence/match-scanner/pkg/scanner"

	cfg "github.com/deepfence/match-scanner/pkg/config"
	"github.com/sirupsen/logrus"
)

type ScanType int

const (
	DirScan ScanType = iota
	ImageScan
	ContainerScan
)

func ScanTypeString(st ScanType) string {
	switch st {
	case DirScan:
		return "host"
	case ImageScan:
		return "image"
	case ContainerScan:
		return "container"
	}
	return ""
}

func scanFile(contents io.ReadSeeker, relPath, fileName, fileExtension, layer string, numSecrets *uint, matchedRuleSet map[uint]uint) ([]output.SecretFound, error) {

	secrets, err := signature.MatchPatternSignatures(contents, relPath, fileName, fileExtension, layer, numSecrets, matchedRuleSet)
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func Scan(ctx *tasks.ScanContext,
	stype ScanType,
	filters cfg.Filters,
	namespace, id, scanID string,
	outputFn func(output.SecretFound, string)) error {
	var (
		extract extractor.FileExtractor
		err     error
	)
	switch stype {
	case DirScan:
		extract, err = extractor.NewDirectoryExtractor(filters, id, true)
	case ImageScan:
		extract, err = extractor.NewImageExtractor(filters, namespace, id)
	case ContainerScan:
		extract, err = extractor.NewContainerExtractor(filters, namespace, id)
	default:
		err = fmt.Errorf("invalid request")
	}
	if err != nil {
		return err
	}
	defer extract.Close()

	// results has to be 1 element max
	// to avoid overwriting the buffer entries
	results := make(chan []output.SecretFound)
	defer close(results)

	go func() {
		for malwares := range results {
			for _, malware := range malwares {
				outputFn(malware, scanID)
			}
		}
	}()

	genscan.ApplyScan(context.Background(), extract, func(f extractor.ExtractedFile) {
		if ctx != nil {
			err := ctx.Checkpoint("scan_phase")
			if err != nil {
				return
			}
		}
		matchedRuleSet := map[uint]uint{}
		var count uint
		m, err := scanFile(f.Content, f.Filename, filepath.Base(f.Filename), filepath.Ext(f.Filename), "", &count, matchedRuleSet)
		if err != nil {
			logrus.Infof("file: %v, err: %v", f.Filename, err)
		}

		results <- m
	})
	return nil
}
