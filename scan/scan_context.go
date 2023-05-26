package scan

type ScanContext struct {
	ScanID         string
	Aborted        bool
	ScanStatusChan chan bool
}

func NewScanContext(scanID string) *ScanContext {
	statusChan := make(chan bool)
	return &ScanContext{scanID, false, statusChan}
}
