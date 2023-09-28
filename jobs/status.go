package jobs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/scan"
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

func StartStatusReporter(scanCtx *scan.ScanContext) chan error {
	res := make(chan error)
	startScanJob()
	scan_id := scanCtx.ScanID
	opts := core.GetSession().Options

	//If we don't get any active status back within threshold,
	//we consider the scan job as dead
	threshold := *opts.InactiveThreshold
	go func() {
		defer stopScanJob()
		ticker := time.NewTicker(30 * time.Second)
		var err error
		ts := time.Now()
		core.GetSession().Log.Error("SecretScan StatusReporter started, scan_id: %s", scan_id)
	loop:
		for {
			select {
			case err = <-res:
				break loop
			case <-scanCtx.ScanStatusChan:
				ts = time.Now()
			case <-ticker.C:
				if scanCtx.Stopped.Load() || scanCtx.Aborted.Load() {
					continue loop
				}

				elapsed := int(time.Since(ts).Seconds())
				if elapsed > threshold {
					scanCtx.Aborted.Store(true)
				} else {
					writeSecretScanStatus("IN_PROGRESS", scan_id, "")
				}
			}
		}

		if scanCtx.Aborted.Load() == true {
			writeSecretScanStatus("ERROR", scan_id, scan.AbortError.Error())
		} else if scanCtx.Stopped.Load() == true {
			writeSecretScanStatus("CANCELLED", scan_id, "Scan stopped by user")
		} else if err != nil {
			writeSecretScanStatus("ERROR", scan_id, err.Error())
		} else {
			writeSecretScanStatus("COMPLETE", scan_id, "")
		}

		core.GetSession().Log.Error("SecretScan StatusReporter stopped, scan_id: %s", scan_id)
	}()
	return res
}
