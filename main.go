package main

import (
	"context"
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
	"time"

	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"

	"golang.org/x/crypto/ssh"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"

	"github.com/hallowauth/hallow/kmssigner"
)

var defaultAllowedKeyTypes = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoSKECDSA256,
}

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

// User ARNs are from IAM, and can take a few forms. The reason why
// we can't use them directly is that ARNs from STS can have some non-determinism
// in them, such as the session name.
//
// As a result, we'll pass through the ARN if it's an IAM ARN, but if it's
// STS, we'll trim the ARN down to the first two blocks.
//
// For more information on this class of nonsense, you may consider
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
// for some bedtime reading.
func createPrincipalName(userArn arn.ARN) (string, error) {
	switch userArn.Service {
	case "sts":
		chunks := strings.Split(userArn.Resource, "/")
		if len(chunks) == 0 {
			return "", fmt.Errorf("hallow: user arn resource is missing")
		}
		switch chunks[0] {
		case "assumed-role":
			if len(chunks) != 3 {
				return "", fmt.Errorf("hallow: malformed assumed-role resource")
			}
			userArn.Resource = fmt.Sprintf("%s/%s", chunks[0], chunks[1])
			return userArn.String(), nil
		default:
			return "", fmt.Errorf("hallow: unsupported sts resource type")
		}
	case "iam":
		// for IAM, we can have a few formats, but all are deterministic
		// and stable.
		return userArn.String(), nil
	default:
		return "", fmt.Errorf("hallow: unknown userArn service")
	}
}

func (c *config) validatePublicKey(sshPubKey ssh.PublicKey) error {
	_, ok := sshPubKey.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("hallow: ssh public key is not a CryptoPublicKey")
	}

	pubKey := sshPubKey.(ssh.CryptoPublicKey).CryptoPublicKey()

	switch pubKey.(type) {
	case *rsa.PublicKey:
		smallestAcceptedSize := 2048
		if pubKey.(*rsa.PublicKey).N.BitLen() < smallestAcceptedSize {
			return fmt.Errorf("hallow: rsa: key size is too small")
		}
		return nil
	case *ecdsa.PublicKey, *ed25519.PublicKey:
		return nil
	default:
		return fmt.Errorf("hallow: public key is of an unknown type, can't validate")
	}
}

func (c *config) handleRequest(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	userArn, err := arn.Parse(event.RequestContext.Identity.UserArn)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Incoming ARN is invalid")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil
	}

	host, ok := event.Headers["Host"]
	if !ok {
		log.Warn("Host header is not present!")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil
	}

	principal, err := createPrincipalName(userArn)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Incoming ARN isn't a valid principal")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil
	}

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
		err := fmt.Errorf("hallow: Disallowed public key type: %s", publicKey.Type())
		l.WithFields(log.Fields{
			"hallow.allowed_key_types": c.allowedKeyTypes,
			"error":                    err,
		}).Warn("Incoming SSH key is not the right type")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil
	}

	if err := c.validatePublicKey(publicKey); err != nil {
		l.WithFields(log.Fields{
			"hallow.allowed_key_types": c.allowedKeyTypes,
			"error":                    err,
		}).Warn("Key failed public key validation checks")
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
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-agent-forwarding":  "",
				"permit-port-forwarding":   "",
				"permit-pty":               "",
				"permit-user-rc":           "",
				"hallow-host@dc.cant.vote": host,
			},
		},
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
		Body:       string(ssh.MarshalAuthorizedKey(sshCert)),
		StatusCode: 200,
	}, nil
}

func main() {
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

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		panic(err)
	}

	c := &config{
		ca: CA{
			Rand:   rand.Reader,
			Signer: sshSigner,
		},
		certAge:         30 * time.Minute,
		allowedKeyTypes: allowedKeyTypes,
	}
	lambda.Start(c.handleRequest)
}
