package main

import (
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/urfave/cli/v2"

	"github.com/hallowauth/hallow/client"
)

//
func hallowClientFromCLI(c *cli.Context) client.Client {
	return client.New(session.New(), http.DefaultClient, c.String("endpoint"))
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
		},
	}
	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
