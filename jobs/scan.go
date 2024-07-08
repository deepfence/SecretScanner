package jobs

import (
	"encoding/json"
	"strings"
	"sync"

	pb "github.com/deepfence/agent-plugins-grpc/srcgo"
	log "github.com/sirupsen/logrus"
)

var ScanMap sync.Map

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

func WriteSingleScanData(secret *pb.SecretInfo, scan_id string) {
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
