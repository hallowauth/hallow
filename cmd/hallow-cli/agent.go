package main

import (
	log "github.com/sirupsen/logrus"
	"net"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	AgentCommand = &cli.Command{
		Name:   "ssh-add",
		Usage:  "Generate a new ssh key, and add the key and certificate to an agent",
		Action: Agent,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "comment",
				Value: "hallow",
			},
			&cli.StringFlag{
				Name:    "ssh-auth-sock",
				EnvVars: []string{"SSH_AUTH_SOCK"},
				Value:   "",
			},
		},
	}
)

//
func Agent(c *cli.Context) error {
	hallow := hallowClientFromCLI(c)
	_ = hallow

	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.WithFields(log.Fields{
			"ssh_auth_sock": socket,
			"error":         err,
		}).Warn("failed to open SSH_AUTH_SOCK")
		return err
	}

	agentClient := agent.NewClient(conn)

	comment := c.String("comment")

	privKey, pubKey, err := hallow.GenerateAndRequestCertificate(
		c.Context,
		comment,
	)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Warn("failed to request Certificate")
		return err
	}
	log.Debug("Certificate was signed by Hallow")

	cert := pubKey.(*ssh.Certificate)

	if err := agentClient.Add(agent.AddedKey{
		PrivateKey:  privKey,
		Certificate: cert,
		Comment:     comment,
	}); err != nil {
		log.WithFields(log.Fields{
			"ssh_auth_sock": socket,
			"error":         err,
		}).Warn("failed to add Certifciate to agent")
		return err
	}

	return nil
}
