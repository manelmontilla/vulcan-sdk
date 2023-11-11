// Package checktype exposed the types needed to develop a checktype.
package checktype

import (
	"context"

	"github.com/manelmontilla/vulcan-sdk/check"
)

type Checktype interface {
	Run(ctx context.Context, target, assetType string, opts string, state check.State) error
	CleanUp(ctx context.Context, target, assetType, opts string)
}
