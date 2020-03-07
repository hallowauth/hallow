package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/urfave/cli/v2"

	"github.com/hallowauth/hallow/client"
)

var (
	SSHCommand = &cli.Command{
		Name:   "ssh",
		Usage:  "SSH into a server with hallow.",
		Action: SSH,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "key-id",
				Value: client.DefaultComment(),
				Usage: "KeyID to use for the SSH Certificate",
			},
		},
	}
)

func SSH(c *cli.Context) error {
	if c.NArg() != 1 {
		return fmt.Errorf("ssh takes exactly one argument")
	}

	hallow := hallowClientFromCLI(c)

	signer, sshCert, err := hallow.GenerateAndRequestCertificate(
		c.Context,
		client.KeyTypeECDSAP256,
		c.String("key-id"),
	)
	if err != nil {
		return err
	}
	sshArgs, err := client.SSHCLI(signer, sshCert, c.Args().Get(0))
	if err != nil {
		return err
	}
	command := exec.CommandContext(c.Context, sshArgs[0], sshArgs[1:]...)
	command.Env = os.Environ()
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr

	return command.Run()
}
