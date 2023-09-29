package jobs

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"

	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
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
				return writeSecretScanStatus(ss.ScanId, ss.ScanStatus, ss.ScanMessage)
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

		var secrets chan output.SecretFound

		if r.GetPath() != "" {
			var isFirstSecret bool = true
			secrets, err = scan.ScanSecretsInDirStream("", r.GetPath(), r.GetPath(),
				&isFirstSecret, scanCtx)
			if err != nil {
				return
			}
		} else if r.GetImage() != nil && r.GetImage().Name != "" {
			secrets, err = scan.ExtractAndScanImageStream(r.GetImage().Name, scanCtx)
			if err != nil {
				return
			}
		} else if r.GetContainer() != nil && r.GetContainer().Id != "" {
			secrets, err = scan.ExtractAndScanContainerStream(r.GetContainer().Id,
				r.GetContainer().Namespace, scanCtx)
			if err != nil {
				return
			}
		} else {
			err = fmt.Errorf("Invalid request")
			return
		}

		for secret := range secrets {
			writeSingleScanData(output.SecretToSecretInfo(secret), r.ScanId)
		}
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
			fmt.Println("Error marshalling json: ", err)
			continue
		}
		err = writeScanDataToFile(string(byteJson), scanFilename)
		if err != nil {
			fmt.Println("Error in sending data to secretScanIndex:" + err.Error())
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
		fmt.Println("Error marshalling json: ", err)
		return
	}
	err = writeScanDataToFile(string(byteJson), scanFilename)
	if err != nil {
		fmt.Println("Error in sending data to secretScanIndex:" + err.Error())
		return
	}
}
