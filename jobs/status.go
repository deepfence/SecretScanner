package jobs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func writeSecretScanStatus(status, scan_id, scan_message string) error {
	var secretScanLogDoc = make(map[string]interface{})
	secretScanLogDoc["scan_id"] = scan_id
	secretScanLogDoc["scan_status"] = status
	secretScanLogDoc["scan_message"] = scan_message

	byteJson, err := json.Marshal(secretScanLogDoc)
	if err != nil {
		return err
	}

	err = writeScanDataToFile(string(byteJson), scanStatusFilename)
	if err != nil {
		return err
	}
	return nil
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
