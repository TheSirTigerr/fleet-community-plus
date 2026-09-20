// Package fleetctl is a compatibility facade for Community+ CLI extensions.
package fleetctl

import (
	communityfleetctl "github.com/fleetdm/fleet/v4/server/communityplus/fleetctl"
	"github.com/urfave/cli/v2"
)

func UpdatesCommand() *cli.Command {
	return communityfleetctl.UpdatesCommand()
}

func LocalWixDirFlag(destination *string) cli.Flag {
	return communityfleetctl.LocalWixDirFlag(destination)
}
