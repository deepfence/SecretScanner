package scan

import "sync/atomic"

type ScanContext struct {
	ScanID         string
	Aborted        atomic.Bool
	ScanStatusChan chan bool
}

func NewScanContext(scanID string) *ScanContext {
	statusChan := make(chan bool)
	obj := ScanContext{scanID, atomic.Bool{}, statusChan}
	obj.Aborted.Store(false)
	return &obj
}
