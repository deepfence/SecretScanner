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
	log "github.com/sirupsen/logrus"
)

var ScanMap sync.Map

const max_secrets_array = 10

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

		var secretsChannel = make(chan []output.SecretFound, max_secrets_array)
		if r.GetPath() != "" {
			var isFirstSecret bool = true
			err = scan.ScanSecretsInDirStream("", r.GetPath(), r.GetPath(),
				&isFirstSecret, scanCtx, secretsChannel)
			if err != nil {
				return
			}
		} else if r.GetImage() != nil && r.GetImage().Name != "" {
			err = scan.ExtractAndScanImageStream(r.GetImage().Name, scanCtx, secretsChannel)
			if err != nil {
				return
			}
		} else if r.GetContainer() != nil && r.GetContainer().Id != "" {
			err = scan.ExtractAndScanContainerStream(r.GetContainer().Id,
				r.GetContainer().Namespace, scanCtx, secretsChannel)
			if err != nil {
				return
			}
		} else {
			err = fmt.Errorf("Invalid request")
			return
		}
		for secrets := range secretsChannel {
			//go func() { //We can introduce a subroutine later if needed. If this send function is slow
			//and we have too many entries in the channel, we run a risk of exiting this when
			//the send function is still in execution.......
			loopCntr := len(secrets)
			for i := 0; i < loopCntr; i++ {
				writeSingleScanData(output.SecretToSecretInfo(secrets[i]), r.ScanId)
			}
			//}()
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
