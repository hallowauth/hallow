package main

import (
	"crypto"
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

// We supply some context from API Gateway to decide which signing key to use.
// This could easily be extended to contain additional context.
type APIGatewayContext struct {
	SourceIP string
	UserArn  string
}

// We just implement a DefaultSigner that always uses HALLOW_KMS_KEY_ARN.
// But you could implement your own SignerChooser that uses APIGatewayContext.
type DefaultSigner struct {
	DefaultKMSKeyARN string
}

func (d DefaultSigner) Choose(context APIGatewayContext) (crypto.Signer, error) {
	sess := session.New()
	return kmssigner.New(kms.New(sess), d.DefaultKMSKeyARN)
}

func main() {
	var err error

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			panic(err)
		}
		log.SetLevel(level)
	}

	sess := session.New()

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

	defaultSigner := DefaultSigner{
		DefaultKMSKeyARN: os.Getenv("HALLOW_KMS_KEY_ARN"),
	}

	c := &config{
		ca: CA{
			Rand:          rand.Reader,
			signerChooser: defaultSigner,
		},
		certValidityDuration: certValidityDuration,
		allowedKeyTypes:      allowedKeyTypes,
		iamClient:            iam.New(sess),
	}
	lambda.Start(c.handleRequest)
}
