package jobs

import (
	"os"
	"sync/atomic"
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

var (
	running_jobs_num atomic.Int32
)

func startScanJob() {
	running_jobs_num.Add(1)
}

func stopScanJob() {
	running_jobs_num.Add(-1)
}

func GetRunningJobCount() int32 {
	return running_jobs_num.Load()
}
