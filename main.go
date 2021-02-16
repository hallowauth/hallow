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

// APIGatewayContext contains key attributes extracted from the incoming request.
// This allows for a clean contract between the Chooser and the Hallow runtime.
//
// If additional information is required, please open a request on Hallow, so
// that we can clearly track the API promises made to the consuming code.
type APIGatewayContext struct {
	SourceIP string
	UserArn  string
}

// DefaultSigner will sign requests using the crypto.Signer contained within
// the struct. This acts as a "passthrough", and should be used unless there's
// a specific need to pick private key material based on the incoming request.
type DefaultSigner struct {
	DefaultCryptoSigner crypto.Signer
}

// Choose implements the SignerChooser interface.
func (d DefaultSigner) Choose(context APIGatewayContext) (crypto.Signer, error) {
	return d.DefaultCryptoSigner, nil
}

func main() {
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel != "" {
		level, err := log.ParseLevel(logLevel)
		if err != nil {
			panic(err)
		}
		log.SetLevel(level)
	}

	sess, err := session.NewSession()
	if err != nil {
		panic(err)
	}
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

	defaultSigner := DefaultSigner{
		DefaultCryptoSigner: signer,
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
