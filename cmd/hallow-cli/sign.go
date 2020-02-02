package main

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

var (
	SignCommand = &cli.Command{
		Name:   "sign",
		Usage:  "sign an ssh public key",
		Action: Sign,
	}
)

//
func Sign(c *cli.Context) error {
	hallow := hallowClientFromCLI(c)
	_ = hallow

	for _, path := range c.Args().Slice() {
		l := log.WithFields(log.Fields{"hallow.public_key.path": path})

		dirname := filepath.Dir(path)
		basename := filepath.Base(path)
		if !strings.HasSuffix(basename, ".pub") {
			l.Warn("filepath doesn't end in .pub")
			return fmt.Errorf("hallow-cli: '%s' does not end with .pub", path)
		}
		certName := fmt.Sprintf("%s-cert.pub", basename[:len(basename)-4])
		certPath := filepath.Join(dirname, certName)

		l.Debug("Opening public key")
		fd, err := os.Open(path)
		if err != nil {
			l.WithFields(log.Fields{"error": err}).Warn("failed to open file")
			return err
		}
		// since we're in a loop, we're not going to defer, since we don't
		// want to overflow open FDs.

		pubkeyBytes, err := ioutil.ReadAll(fd)
		if err != nil {
			l.WithFields(log.Fields{"error": err}).Warn("failed to read public key")
			fd.Close()
			return err
		}
		fd.Close()

		pubKey, comment, _, _, err := ssh.ParseAuthorizedKey(pubkeyBytes)
		if err != nil {
			l.WithFields(log.Fields{"error": err}).Warn("failed to parse public key")
			return err
		}

		l.Debug("Requesting Certificate from Hallow")
		pubKey, err = hallow.RequestCertificate(c.Context, pubKey, comment)
		if err != nil {
			l.WithFields(log.Fields{"error": err}).Warn("hallow failed to sign our key")
			return err
		}

		l = l.WithFields(log.Fields{"hallow.certificate.path": certPath})
		l.Debug("Creating certificate file")
		fd, err = os.Create(certPath)
		if err != nil {
			l.WithFields(log.Fields{"error": err}).Warn("can't write cert to disk")
			return err
		}

		_, err = fd.Write(ssh.MarshalAuthorizedKey(pubKey))
		if err != nil {
			l.WithFields(log.Fields{"error": err}).Warn("failed to write cert to open file")
			return err
		}
		l.Debug("Successfully wrote Certificate out")
	}

	return nil
}
