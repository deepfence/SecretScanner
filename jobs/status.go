package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
