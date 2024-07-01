package jobs

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"

	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	log "github.com/sirupsen/logrus"
)

var ScanMap sync.Map

func DispatchScan(r *pb.FindRequest) {
	go func() {
		startScanJob()
		defer stopScanJob()

		var err error
		res, scanCtx := tasks.StartStatusReporter(
			r.ScanId,
			func(ss tasks.ScanStatus) error {
				return writeSecretScanStatus(ss.ScanStatus, ss.ScanId, ss.ScanMessage)
			},
			tasks.StatusValues{
				IN_PROGRESS: "IN_PROGRESS",
				CANCELLED:   "CANCELLED",
				FAILED:      "ERROR",
				SUCCESS:     "COMPLETE",
			},
			time.Minute*20,
		)

		ScanMap.Store(r.ScanId, scanCtx)

		defer func() {
			ScanMap.Delete(r.ScanId)
			res <- err
			close(res)
		}()

		var (
			scanType scan.ScanType
			nodeID   string
		)

		if r.GetPath() != "" {
			scanType = scan.DirScan
			nodeID = r.GetPath()
		} else if r.GetImage() != nil && r.GetImage().Name != "" {
			scanType = scan.ImageScan
			nodeID = r.GetImage().Name
		} else if r.GetContainer() != nil && r.GetContainer().Id != "" {
			scanType = scan.ContainerScan
			nodeID = r.GetContainer().Id
		} else {
			err = fmt.Errorf("Invalid request")
			return
		}

		filters := cfg.Config2Filter(core.GetSession().ExtractorConfig)
		err = scan.Scan(scanCtx, scanType, filters, "", nodeID, r.GetScanId(), func(sf output.SecretFound, s string) {
			writeSingleScanData(output.SecretToSecretInfo(sf), r.ScanId)
		})
	}()
}

type SecretScanDoc struct {
	pb.SecretInfo
	ScanID string `json:"scan_id,omitempty"`
}

func writeMultiScanData(secrets []*pb.SecretInfo, scan_id string) {
	for _, secret := range secrets {
		if SecretScanDir == HostMountDir {
			secret.GetMatch().FullFilename = strings.Replace(secret.GetMatch().GetFullFilename(), SecretScanDir, "", 1)
		}
		secretScanDoc := SecretScanDoc{
			SecretInfo: *secret,
			ScanID:     scan_id,
		}
		byteJson, err := json.Marshal(secretScanDoc)
		if err != nil {
			log.Errorf("Error marshalling json: ", err)
			continue
		}
		err = writeScanDataToFile(string(byteJson), scanFilename)
		if err != nil {
			log.Errorf("Error in sending data to secretScanIndex:" + err.Error())
			continue
		}
	}
}

func writeSingleScanData(secret *pb.SecretInfo, scan_id string) {
	if SecretScanDir == HostMountDir {
		secret.GetMatch().FullFilename = strings.Replace(secret.GetMatch().GetFullFilename(), SecretScanDir, "", 1)
	}
	secretScanDoc := SecretScanDoc{
		SecretInfo: *secret,
		ScanID:     scan_id,
	}
	byteJson, err := json.Marshal(secretScanDoc)
	if err != nil {
		log.Errorf("Error marshalling json: ", err)
		return
	}
	err = writeScanDataToFile(string(byteJson), scanFilename)
	if err != nil {
		log.Errorf("Error in sending data to secretScanIndex:" + err.Error())
		return
	}
}
