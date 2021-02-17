package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/urfave/cli/v2"

	"github.com/hallowauth/hallow/client"
)

//
func hallowClientFromCLI(c *cli.Context) (*client.Client, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	handle := client.New(sess, c.String("endpoint"))
	return &handle, nil
}

//
func keyTypeFromCLI(c *cli.Context) (client.KeyType, error) {
	switch c.String("key-type") {
	case "ecdsa256":
		return client.KeyTypeECDSAP256, nil
	case "ecdsa384":
		return client.KeyTypeECDSAP384, nil
	case "ecdsa521":
		return client.KeyTypeECDSAP521, nil
	case "rsa2048":
		return client.KeyTypeRSA2048, nil
	case "rsa4096":
		return client.KeyTypeRSA4096, nil
	case "ed25519":
		return client.KeyTypeED25519, nil
	default:
		return 0, fmt.Errorf("hallow-cli: unknown key type")
	}
}

func main() {
	app := &cli.App{
		Name:  "hallow-cli",
		Usage: "talk to the hallow server",
		Description: `hallow-cli is the refrence program to talk to a hallow endpoint.

   This program contains a number of helpers that are handy when operating or
   interacting with a hallow server, without having to build all the tooling
   to talk to that endpoint yourself.`,
		Before: func(c *cli.Context) error {
			level, err := log.ParseLevel(c.String("log-level"))
			if err != nil {
				return err
			}
			log.SetLevel(level)
			return nil
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				EnvVars: []string{"HALLOW_LOG_LEVEL"},
				Value:   "info",
			},
			&cli.StringFlag{
				Name:    "endpoint",
				EnvVars: []string{"HALLOW_ENDPOINT"},
				Value:   "",
			},
		},
		Commands: []*cli.Command{
			SignCommand,
			GetPubKeyCommand,
			SSHCommand,
			AgentCommand,
		},
		Authors: []*cli.Author{
			&cli.Author{Name: "Alex Gaynor"},
			&cli.Author{Name: "Paul Tagliamonte"},
		},
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
