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
func hallowClientFromCLI(c *cli.Context) client.Client {
	return client.New(session.New(), c.String("endpoint"))
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
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
