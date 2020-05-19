package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
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
	ca                   CA
	iamClient            iamiface.IAMAPI
	allowedKeyTypes      []string
	certValidityDuration time.Duration
}

func getAdditionalPrincipalsForRole(ctx context.Context, iamClient iamiface.IAMAPI, roleName string) ([]string, error) {
	response, err := iamClient.GetRoleWithContext(ctx, &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, err
	}
	for _, tag := range response.Role.Tags {
		if aws.StringValue(tag.Key) == "hallow.additional_principals" {
			return strings.Split(aws.StringValue(tag.Value), ","), nil
		}
	}
	return nil, nil
}

var errUnsupportedStsResourceType = errors.New("hallow: unsupported sts resource type")
var errUnknowUserArnService = errors.New("hallow: unknown userArn service")
var errMalformedAssumedRoleArn = errors.New("hallow: malformed assumed-role resource")

// createPrincipalNames selects which principals will be assigned for a
// certificate requested by the provided ARN.
//
// User ARNs are from IAM, and can take a few forms. The reason why
// we can't use them directly is that ARNs from STS can have some
// non-determinism in them, such as the session name.
//
// As a result, we'll pass through the ARN if it's an IAM ARN, but if it's
// STS assumed-role ARN, we'll trim it down to the first two blocks.
//
// For more information on this class of nonsense, you may consider
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
// for some bedtime reading.
//
// For assumed role ARNs we will additionally look up the role, and if it has a
// Tag named "hallow.additional_principals" will return them.
func createPrincipalNames(ctx context.Context, iamClient iamiface.IAMAPI, userArn arn.ARN) ([]string, error) {
	switch userArn.Service {
	case "sts":
		chunks := strings.Split(userArn.Resource, "/")
		switch chunks[0] {
		case "assumed-role":
			if len(chunks) != 3 {
				return nil, errMalformedAssumedRoleArn
			}
			userArn.Resource = fmt.Sprintf("%s/%s", chunks[0], chunks[1])
			principals := []string{userArn.String()}
			additionalPrincipals, err := getAdditionalPrincipalsForRole(
				ctx, iamClient, chunks[1])
			if err != nil {
				return nil, err
			}
			return append(principals, additionalPrincipals...), nil
		default:
			return nil, errUnsupportedStsResourceType
		}
	case "iam":
		// for IAM, we can have a few formats, but all are deterministic
		// and stable.
		return []string{userArn.String()}, nil
	default:
		return nil, errUnknowUserArnService
	}
}

var errUnknownKeyType = errors.New("hallow: public key is of an unknown type, can't validate")
var errSmallRsaKey = errors.New("hallow: rsa: key size is too small")

func (c *config) validatePublicKey(sshPubKey ssh.PublicKey) error {
	cryptoPubKey, ok := sshPubKey.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("hallow: ssh public key is not a CryptoPublicKey")
	}

	switch pubKey := cryptoPubKey.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		smallestAcceptedSize := 2048
		if pubKey.N.BitLen() < smallestAcceptedSize {
			return errSmallRsaKey
		}
		return nil
	case *ecdsa.PublicKey, ed25519.PublicKey:
		return nil
	default:
		return errUnknownKeyType
	}
}

func (c *config) handleRequest(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	l := log.WithField("request.client_ip", event.RequestContext.Identity.SourceIP)

	userArn, err := arn.Parse(event.RequestContext.Identity.UserArn)
	if err != nil {
		l.WithError(err).Warn("Incoming ARN is invalid")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil
	}

	host, ok := event.Headers["Host"]
	if !ok {
		l.Warn("Host header is not present!")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil
	}

	principals, err := createPrincipalNames(ctx, c.iamClient, userArn)
	if err != nil {
		l.WithError(err).Warn("Incoming ARN isn't a valid principal")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil
	}

	publicKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(event.Body))
	if err != nil {
		l.WithError(err).Warn("Incoming SSH key is invalid")
		return events.APIGatewayProxyResponse{
			Body:       "Malformed request",
			StatusCode: 400,
		}, nil

	}
	l = l.WithFields(log.Fields{
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
		l.WithError(err).Warn("Can't create a nonce")
		return events.APIGatewayProxyResponse{
			Body:       "Internal server error",
			StatusCode: 500,
		}, nil
	}

	serial := binary.LittleEndian.Uint64(b[:])
	template := ssh.Certificate{
		Key:             publicKey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           comment,
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-time.Minute * 1).Unix()),
		ValidBefore:     uint64(time.Now().Add(c.certValidityDuration).Unix()),
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

	sshCert, err := c.ca.Sign(template)
	if err != nil {
		l.WithError(err).Warn("The CA can't sign the Certificate")
		return events.APIGatewayProxyResponse{
			Body:       "Internal server error",
			StatusCode: 500,
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
