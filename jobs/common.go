package jobs

import "sync/atomic"

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
