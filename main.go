package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"

	"github.com/alex/hallow/kmssigner"
)

func stringSliceContains(s string, v []string) bool {
	for _, x := range v {
		if s == x {
			return true
		}
	}
	return false
}

type config struct {
	ca              CA
	allowedKeyTypes []string
	certAge         time.Duration
}

func (c *config) handleRequest(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	principal := event.RequestContext.Identity.UserArn
	publicKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(event.Body))
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Incoming SSH key is invalid")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil

	}
	l := log.WithFields(log.Fields{
		"request.comment":         comment,
		"request.public_key.type": publicKey.Type(),
	})
	if !stringSliceContains(publicKey.Type(), c.allowedKeyTypes) {
		err := fmt.Errorf("Disallowed public key type: %s", publicKey.Type())
		l.WithFields(log.Fields{
			"hallow.allowed_key_types": c.allowedKeyTypes,
			"error":                    err,
		}).Warn("Incoming SSH key is not the right type")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil
	}

	var b [8]byte
	if _, err := c.ca.Rand.Read(b[:]); err != nil {
		l.WithFields(log.Fields{"error": err}).Warn("Can't create a nonce")
		return events.APIGatewayProxyResponse{
			Body:       "Internal server error",
			StatusCode: 500,
		}, nil
	}

	serial := int64(binary.LittleEndian.Uint64(b[:]))
	template := ssh.Certificate{
		Key:             publicKey,
		Serial:          uint64(serial),
		CertType:        ssh.UserCert,
		KeyId:           comment,
		ValidPrincipals: []string{principal},
		ValidAfter:      uint64(time.Now().Add(-time.Second * 5).Unix()),
		ValidBefore:     uint64(time.Now().Add(c.certAge).Unix()),
	}

	template.Permissions.CriticalOptions = map[string]string{}
	template.Permissions.Extensions = map[string]string{
		// "permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}

	sshCert, _, err := c.ca.SignAndParse(template)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Warn("The CA can't sign the Certificate")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil
	}
	l.WithFields(log.Fields{
		"response.certificate.type":         sshCert.Type(),
		"response.certificate.serial":       serial,
		"response.certificate.key_id":       template.KeyId,
		"response.certificate.valid_after":  template.ValidAfter,
		"response.certificate.valid_before": template.ValidBefore,
		"response.certificate.principals":   template.ValidPrincipals,
	}).Info("CA Signed the Public Key")

	return events.APIGatewayProxyResponse{
		Body: fmt.Sprintf(
			"%s %s\n",
			sshCert.Type(),
			base64.StdEncoding.EncodeToString(sshCert.Marshal()),
		),
		StatusCode: 200,
	}, nil
}

func main() {
	sess := session.New()
	signer, err := kmssigner.New(kms.New(sess), os.Getenv("HALLOW_KMS_KEY_ARN"))
	if err != nil {
		panic(err)
	}

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		panic(err)
	}

	c := &config{
		ca: CA{
			Rand:   rand.Reader,
			Signer: sshSigner,
		},
		certAge: 30 * time.Minute,
		allowedKeyTypes: []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoSKED25519,
			ssh.KeyAlgoSKECDSA256,
		},
	}
	lambda.Start(c.handleRequest)
}
