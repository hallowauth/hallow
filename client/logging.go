package client

import (
	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"
)

// Create a new log.Entry from an ssh.Certificate
func logWithCertificate(sshCert *ssh.Certificate) *log.Entry {
	return log.WithFields(log.Fields{
		"hallow.certificate.type":         sshCert.Type(),
		"hallow.certificate.serial":       sshCert.Serial,
		"hallow.certificate.key_id":       sshCert.KeyId,
		"hallow.certificate.valid_after":  sshCert.ValidAfter,
		"hallow.certificate.valid_before": sshCert.ValidBefore,
		"hallow.certificate.principals":   sshCert.ValidPrincipals,
	})
}
