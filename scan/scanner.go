package scan

import (
	"fmt"
	"io"
	"path/filepath"
	"sync"

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

func scanFile(contents io.ReadSeeker, relPath, fileName, fileExtension, layer string) ([]output.SecretFound, error) {

	simpleSecrets, err := signature.MatchSimpleSignatures(contents, relPath, fileName, fileExtension, layer)
	if err != nil {
		return nil, err
	}

	secrets, err := signature.MatchPatternSignatures(contents, relPath, fileName, fileExtension, layer)
	if err != nil {
		return nil, err
	}

	return append(simpleSecrets, secrets...), nil
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

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for secrets := range results {
			for _, secret := range secrets {
				outputFn(secret, scanID)
			}
		}
	}()
	genscan.ApplyScan(ctx.Context, extract, func(f extractor.ExtractedFile) {
		if ctx != nil {
			err := ctx.Checkpoint("scan_phase")
			if err != nil {
				return
			}
		}
		logrus.Infof("Scanning file: %v", f.Filename)
		s, err := scanFile(f.Content, f.Filename, filepath.Base(f.Filename), filepath.Ext(f.Filename), "")
		if err != nil {
			logrus.Infof("file: %v, err: %v", f.Filename, err)
		}

		results <- s
	})

	close(results)
	wg.Wait()

	return nil
}
