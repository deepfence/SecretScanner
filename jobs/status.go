package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/scan"

	pb "github.com/deepfence/agent-plugins-grpc/proto"
)

var (
	scanStatusFilename = getDfInstallDir() + "/var/log/fenced/secret-scan-log/secret_scan_log.log"
	scanFilename       = getDfInstallDir() + "/var/log/fenced/secret-scan/secret_scan.log"
	SecretScanDir      = "/"
)

const (
	HostMountDir = "/fenced/mnt/host"
)

func init() {
	if os.Getenv("DF_SERVERLESS") == "true" {
		SecretScanDir = "/"
	} else {
		SecretScanDir = HostMountDir
	}
}

func writeSecretScanStatus(status, scan_id, scan_message string) {
	var secretScanLogDoc = make(map[string]interface{})
	secretScanLogDoc["scan_id"] = scan_id
	secretScanLogDoc["scan_status"] = status
	secretScanLogDoc["scan_message"] = scan_message

	byteJson, err := json.Marshal(secretScanLogDoc)
	if err != nil {
		fmt.Println("Error marshalling json for secret-logs-status: ", err)
		return
	}

	err = writeScanDataToFile(string(byteJson), scanStatusFilename)
	if err != nil {
		fmt.Println("Error in sending data to secret-logs-status to mark in progress:" + err.Error())
		return
	}
}

func writeScanDataToFile(secretScanMsg string, filename string) error {
	err := os.MkdirAll(filepath.Dir(filename), 0755)
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}

	defer f.Close()

	secretScanMsg = strings.Replace(secretScanMsg, "\n", " ", -1)
	if _, err = f.WriteString(secretScanMsg + "\n"); err != nil {
		return err
	}
	return nil
}

func getDfInstallDir() string {
	installDir, exists := os.LookupEnv("DF_INSTALL_DIR")
	if exists {
		return installDir
	} else {
		return ""
	}
}

func startStatusReporter(ctx context.Context, scan_id string) chan error {
	res := make(chan error)
	startScanJob()
	go func() {
		defer stopScanJob()
		var err, abort error
	loop:
		for {
			select {
			case err = <-res:
				break loop
			case <-ctx.Done():
				abort = ctx.Err()
				break loop
			case <-time.After(30 * time.Second):
				writeSecretScanStatus("IN_PROGRESS", scan_id, "")
			}
		}
		if abort != nil {
			writeSecretScanStatus("CANCELLED", scan_id, abort.Error())
			return
		}
		if err != nil {
			writeSecretScanStatus("ERROR", scan_id, err.Error())
			return
		}
		writeSecretScanStatus("COMPLETE", scan_id, "")
	}()
	return res
}

type SecretScanDoc struct {
	pb.SecretInfo
	ScanID string `json:"scan_id,omitempty"`
}

func writeScanData(secrets []*pb.SecretInfo, scan_id string) {
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

func DispatchScan(r *pb.FindRequest) {

	go func() {
		var err error
		res := startStatusReporter(context.Background(), r.ScanId)
		defer func() {
			res <- err
			close(res)
		}()
		var outputSecrets []*pb.SecretInfo

		if r.GetPath() != "" {
			var isFirstSecret bool = true
			var numSecrets uint = 0

			secrets, err := scan.ScanSecretsInDir("", r.GetPath(), r.GetPath(), &isFirstSecret, &numSecrets, nil)
			if err != nil {
				return
			}
			outputSecrets = output.SecretsToSecretInfos(secrets)
		} else if r.GetImage() != nil && r.GetImage().Name != "" {
			res, err := scan.ExtractAndScanImage(r.GetImage().Name)
			if err != nil {
				return
			}
			outputSecrets = output.SecretsToSecretInfos(res.Secrets)
		} else if r.GetContainer() != nil && r.GetContainer().Id != "" {
			res, err := scan.ExtractAndScanContainer(r.GetContainer().Id, r.GetContainer().Namespace)
			if err != nil {
				return
			}
			outputSecrets = output.SecretsToSecretInfos(res.Secrets)
		} else {
			err = fmt.Errorf("Invalid request")
			return
		}

		writeScanData(outputSecrets, r.ScanId)
	}()
}
