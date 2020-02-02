package main

import (
	"github.com/urfave/cli/v2"
)

var (
	SignCommand = &cli.Command{
		Name:   "sign",
		Usage:  "sign an ssh public key",
		Action: Sign,
	}
)

func Sign(c *cli.Context) error {
	return nil
}
