package main

import (
	"crypto/rand"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/kms"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"

	"github.com/hallowauth/hallow/kmssigner"
)

var (
	defaultCertValidityDuration = 30 * time.Minute
	defaultAllowedKeyTypes      = []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoSKECDSA256,
	}
)

func main() {
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			panic(err)
		}
		log.SetLevel(level)
	}

	sess := session.New()
	signer, err := kmssigner.New(kms.New(sess), os.Getenv("HALLOW_KMS_KEY_ARN"))
	if err != nil {
		panic(err)
	}

	allowedKeyTypes := defaultAllowedKeyTypes
	allowedKeyTypesStr := os.Getenv("HALLOW_ALLOWED_KEY_TYPES")
	if allowedKeyTypesStr != "" {
		allowedKeyTypes = strings.Split(allowedKeyTypesStr, " ")
	}
	log.WithFields(log.Fields{
		"hallow.allowed_key_types": allowedKeyTypes,
	}).Debug("Loaded allowed key types")

	certValidityDuration := defaultCertValidityDuration
	certValidityDurationStr := os.Getenv("HALLOW_CERT_VALIDITY_DURATION")
	if certValidityDurationStr != "" {
		certValidityDuration, err = time.ParseDuration(certValidityDurationStr)
		if err != nil {
			panic(err)
		}
	}
	log.WithFields(log.Fields{
		"hallow.cert_age": certValidityDuration,
	}).Debug("Loaded certificate age")

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		panic(err)
	}

	c := &config{
		ca: CA{
			Rand:   rand.Reader,
			Signer: sshSigner,
		},
		certValidityDuration: certValidityDuration,
		allowedKeyTypes:      allowedKeyTypes,
		iamClient:            iam.New(sess),
	}
	lambda.Start(c.handleRequest)
}
