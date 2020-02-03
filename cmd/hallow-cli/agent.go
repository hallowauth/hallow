package main

import (
	log "github.com/sirupsen/logrus"
	"net"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh/agent"

	"github.com/hallowauth/hallow/client"
)

var (
	AgentCommand = &cli.Command{
		Name:   "ssh-add",
		Usage:  "Generate a new ssh key, and add the key and certificate to an agent",
		Action: Agent,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "key-id",
				Value: client.DefaultComment(),
				Usage: "KeyID to use for the SSH Certificate",
			},
			&cli.StringFlag{
				Name:    "ssh-auth-sock",
				Usage:   "Path to the ssh agent socket",
				EnvVars: []string{"SSH_AUTH_SOCK"},
				Value:   "",
			},
			&cli.StringFlag{
				Name:  "key-type",
				Usage: "Key type to generate [ecdsa256|ecdsa384|ecdsa521|ed25519]",
				Value: "ecdsa384",
			},
		},
	}
)

//
func Agent(c *cli.Context) error {
	hallow := hallowClientFromCLI(c)

	keyType, err := keyTypeFromCLI(c)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Warn("failed to resolve generated key type")
		return err
	}
	l := log.WithFields(log.Fields{
		"hallow-cli.key_type": keyType,
	})
	l.Trace("got key type")

	socket := os.Getenv("SSH_AUTH_SOCK")
	l = l.WithFields(log.Fields{"ssh_auth_sock": socket})
	conn, err := net.Dial("unix", socket)
	if err != nil {
		l.WithFields(log.Fields{
			"error": err,
		}).Warn("failed to open SSH_AUTH_SOCK")
		return err
	}

	agentClient := agent.NewClient(conn)
	l.Trace("opened agent connection")

	keyId := c.String("key-id")
	_, err = hallow.GetOrGenerateFromAgent(
		c.Context,
		agentClient,
		keyType,
		keyId,
	)
	if err != nil {
		l.WithFields(log.Fields{
			"error": err,
		}).Warn("failed to get or create certificate")
		return err
	}

	return nil
}
