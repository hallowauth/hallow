package main

import (
	"fmt"

	"github.com/alex/hallow/kmssigner"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

var (
	GetPubKeyCommand = &cli.Command{
		Name:   "get-pub-key",
		Usage:  "Gets the SSH public key for the CA KMS key",
		Action: GetPubKey,
	}
)

func GetPubKey(c *cli.Context) error {
	sess := session.New()

	for _, keyArn := range c.Args().Slice() {
		signer, err := kmssigner.New(kms.New(sess), keyArn)
		if err != nil {
			return err
		}
		sshPubKey, err := ssh.NewPublicKey(signer.Public())
		if err != nil {
			return err
		}
		fmt.Print(string(ssh.MarshalAuthorizedKey(sshPubKey)))
	}

	return nil
}
