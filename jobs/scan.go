package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"

	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
)

var ScanMap sync.Map

func DispatchScan(r *pb.FindRequest) {

	go func() {
		scanCtx := scan.NewScanContext(r.ScanId)
		var err error
		res := StartStatusReporter(context.Background(), scanCtx)

		ScanMap.Store(scanCtx.ScanID, scanCtx)

		defer func() {
			ScanMap.Delete(scanCtx.ScanID)
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
