package main

import (
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "hallow-cli",
		Usage: "talk to the hallow server",
		Commands: []*cli.Command{
			SignCommand,
			GetPubKeyCommand,
		},
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
