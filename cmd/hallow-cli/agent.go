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
				Name:  "key-id",
				Value: "hallow",
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
				Usage: "Key type to generate [ecdsa|ed25519]",
				Value: "ecdsa",
			},
			&cli.IntFlag{
				Name:  "key-bits",
				Usage: "for ecdsa, this will select curve sizes [256|384|521]",
				Value: 384,
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
	privKey, pubKey, err := hallow.GenerateAndRequestCertificate(
		c.Context,
		keyType,
		keyId,
	)
	if err != nil {
		l.WithFields(log.Fields{
			"error": err,
		}).Warn("failed to request Certificate")
		return err
	}

	cert := pubKey.(*ssh.Certificate)
	l = l.WithFields(log.Fields{
		"hellow-cli.certificate.principals": cert.ValidPrincipals,
	})
	l.Debug("Certificate was signed by Hallow")

	if err := agentClient.Add(agent.AddedKey{
		PrivateKey:  privKey,
		Certificate: cert,
		Comment:     keyId,
	}); err != nil {
		l.WithFields(log.Fields{
			"error": err,
		}).Warn("failed to add Certifciate to agent")
		return err
	}

	return nil
}
