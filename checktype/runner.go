package checktype

import (
	"context"

	"github.com/manelmontilla/vulcan-sdk/check"
)

// Runner defines the interface a checktype must implement to define its run
// logic.
type Runner interface {
	Run(ctx context.Context, target string, assetType AssetType, options Options, state check.State) error
	CleanUp(ctx context.Context, target string, assetType AssetType, options Options)
}
