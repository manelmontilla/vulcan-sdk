package check

import (
	"github.com/manelmontilla/vulcan-sdk/check/report"
)

type State struct {
	ProgressReporter
	*report.ResultData
}

// ProgressReporter is intended to be used by the sdk.
type ProgressReporter interface {
	SetProgress(float32)
}
