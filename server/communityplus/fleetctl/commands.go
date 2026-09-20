// Package fleetctl contains Community+ CLI compatibility commands.
package fleetctl

import (
	"errors"

	"github.com/urfave/cli/v2"
)

func UpdatesCommand() *cli.Command {
	return &cli.Command{
		Name:  "updates",
		Usage: "Manage Community+ update policies",
		Action: func(*cli.Context) error {
			return errors.New("the Community+ updates command is not implemented yet")
		},
	}
}

func LocalWixDirFlag(destination *string) cli.Flag {
	return &cli.StringFlag{
		Name:        "local-wix-dir",
		Usage:       "Use a local WiX toolset directory when building Windows packages",
		Destination: destination,
		Hidden:      true,
	}
}
