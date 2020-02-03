package client

import (
	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/ssh"
)

// Create a new log.Entry from an ssh.Certificate
func logWithCertificate(sshCert *ssh.Certificate) *log.Entry {
	return log.WithFields(log.Fields{
		"response.certificate.type":         sshCert.Type(),
		"response.certificate.serial":       sshCert.Serial,
		"response.certificate.key_id":       sshCert.KeyId,
		"response.certificate.valid_after":  sshCert.ValidAfter,
		"response.certificate.valid_before": sshCert.ValidBefore,
		"response.certificate.principals":   sshCert.ValidPrincipals,
	})
}
