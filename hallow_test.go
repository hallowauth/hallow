package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type fakeIAMAPI struct {
	iamiface.IAMAPI
	// Map of {roleName => "additional,principals"}
	roleAdditionalPrincipals map[string]string
}

func (c fakeIAMAPI) GetRoleWithContext(_ context.Context, req *iam.GetRoleInput, _ ...request.Option) (*iam.GetRoleOutput, error) {
	tags := []*iam.Tag{}
	if principals, ok := c.roleAdditionalPrincipals[aws.StringValue(req.RoleName)]; ok {
		tags = append(tags, &iam.Tag{
			Key:   aws.String("hallow.additional_principals"),
			Value: aws.String(principals),
		})
	}
	return &iam.GetRoleOutput{
		Role: &iam.Role{
			RoleName: req.RoleName,
			Tags:     tags,
		},
	}, nil
}

func TestCreatePrincipalNames(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		arn         string
		iamClient   iamiface.IAMAPI
		expected    []string
		expectedErr error
	}{
		{
			arn:       "arn:aws:sts::12345:assumed-role/my-role/comment",
			iamClient: fakeIAMAPI{},
			expected:  []string{"arn:aws:sts::12345:assumed-role/my-role"},
		},
		{
			arn: "arn:aws:sts::12345:assumed-role/my-role/comment",
			iamClient: fakeIAMAPI{
				roleAdditionalPrincipals: map[string]string{
					"my-role": "extra-principal,or-two",
				},
			},
			expected: []string{
				"arn:aws:sts::12345:assumed-role/my-role",
				"extra-principal",
				"or-two",
			},
		},
		{
			arn:      "arn:aws:iam::12345:user/john-doe",
			expected: []string{"arn:aws:iam::12345:user/john-doe"},
		},
		{
			arn:      "arn:aws:iam::12345:user/john-doe",
			expected: []string{"arn:aws:iam::12345:user/john-doe"},
		},
		{
			arn:         "arn:aws:sts::12345:federated-user/john-doe",
			expectedErr: errUnsupportedStsResourceType,
		},
		{
			arn:         "arn:aws:rds:us-east-1:12345:db:database",
			expectedErr: errUnknowUserArnService,
		},
		{
			arn:         "arn:aws:sts::12345:assumed-role/",
			expectedErr: errMalformedAssumedRoleArn,
		},
		{
			arn:         "arn:aws:sts::12345:",
			expectedErr: errUnsupportedStsResourceType,
		},
	} {
		t.Run(c.arn, func(t *testing.T) {
			parsedArn, err := arn.Parse(c.arn)
			require.NoError(t, err)

			principals, err := createPrincipalNames(ctx, c.iamClient, parsedArn)
			if c.expectedErr == nil {
				require.NoError(t, err)
				require.Equal(t, principals, c.expected)
			} else {
				require.Equal(t, err, c.expectedErr)
			}
		})
	}
}

func TestValidatePublicKey(t *testing.T) {
	h := config{}

	for _, c := range []struct {
		pubKey      string
		expectedErr error
	}{
		// Valid keys.
		{
			pubKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOfreF0kMkdJ1ISFvPsucJ7X8UJ07rQV99hQGLYBuSV",
		},
		{
			pubKey: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKEKlDRLGPX1iKEGebvigYpkydGfuok6WQYROznG8XFyH1Se7/p1pXADdJtrnegU2Qn3jgmevHvDKD5VAIyGpB8=",
		},
		{
			pubKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCn9+7X+Uk8NSi7Dv6BRkKLVKz6MAKvX/jYhY7Lq/KfxZGlSPcc4duhisKR+YN7Sooo4xXURNUakzuDqptBZVgjqip7iedAqIlDmwTQsoYW+IVsrDg3T/3SUgAy3CsPcMFEE/S13o/haXa9iHZZl2TEGy7qIY7llUUI33SV/EZ3JBcznnLUqFVKlfjB5pKUlixkl+aMFOTvHUrwWv4UtOs0oczvrFQLihLj34Wqeq9LpN/6lXtVppzcxcAX3JGvmUx1GM4MJA9wXgex/1SXEvwEgkQjd+bSsdPazAV8+1dAqvbPgbyqSJmeCJ1biu/1FaBB4Zni0Dwjl0Rq/IVJ0Z+V8KUgZvQCMQDmRBxKBfkmIR7zlhR66ZYt/FC3L/QDAM6JAKDGh+dURWuI8h75w8OwCItRIEAvm6w8Rjzbxdjb7DOjA/toiyJBgmLOb2ZgkldtpKM+3VrPBzvPl7tSHPK0K01E4z9huIRPw0/3cvaZxMbJshkwcOok33msKRl7MwdWxI3yhIyoElWzNH8RsRl/171PPh/bxWDAd43uX/YfFkY5h0XHvnPUK2BMWFkJps1zLqrA+qFfQAJxHWLDl0keLaCVmpQs0PG+Q+NsXlSqGNSTN/r6Yz4s/qn0A9aJ651iVcnbusdnBmF/sCKPa0WD78nXyD5uFtbZIyzU0xjq6w==",
		},
		// DSA key
		{
			pubKey:      "ssh-dss AAAAB3NzaC1kc3MAAACBANLlxcoOBh5rcRm3b0hg7kN31pFFesd4rAncMPe230bNabgjqCEblZPyCkqP9D4aktKIqiCk43YjreXkDrB/1a1ST0ZjGu4914eGIW68W1vCtqOqFe21kHWLhh/HhZXlWHLwrHu9RkcMOAghDhj/tlkmgu09WfTnJnuXKqrAIYmnAAAAFQCJjFbwiJP976BeSCX3tNLFzR5JHwAAAIEArAdfNtpmnThMD6guamSKg17vv1MtFCxg7xuP7kweFPFepzD+l/xKXsUq1nnTRFqF4HDsHT0xgXY5567wBfQEqATFBxY7Zd/8298TY8aQbLcjLr+pQ9bQRMjKM2XOjVr31neNSJf51DaCjmvNWMv5vnCBoIDXY72TJvSryIN/W9MAAACAFrPrlKRD746a/Qr0+ZOyUI4GJC0e04zgG9a/tLNh6cNyBn6nVVgyCOLhQqONyhZks4ZUFTHphNpEUGBUgN8Ox4kaYf4wQB6G+SvcprjZrC06RCQGJYS5vFSgNpqrh/6nCAaeDtsFH3Lx5ot/sxQYw2OzTOdkbSRCBV/SNBruDNI=",
			expectedErr: errUnknownKeyType,
		},
		// Small RSA key
		{
			pubKey:      "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC5OXmDKEHLVj7nTnYlO5dOdK0BO1XJasLSaz9H+Psj/V3DZeQyJZFkJzyByQXOZa7DN+WEkqaapFb7ttS90Bb+zQ5raeCl3GiRmAH8peHPiOn3Sp5G9QtLFNlYuVswdzYdONX0NTIhF//L7+fmL83fr6WzdnXKL8iSsxSCBKKS5Q==",
			expectedErr: errSmallRsaKey,
		},
	} {
		t.Run(c.pubKey, func(t *testing.T) {
			sshPubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.pubKey))
			require.NoError(t, err)

			err = h.validatePublicKey(sshPubKey)
			require.Equal(t, err, c.expectedErr)
		})
	}
}

type responseCheck func(t *testing.T, response events.APIGatewayProxyResponse)
type certCheck func(t *testing.T, cert *ssh.Certificate)

func checkStatusCode(code int) responseCheck {
	return func(t *testing.T, response events.APIGatewayProxyResponse) {
		require.Equal(t, response.StatusCode, code)
	}
}

func certChecks(checks ...certCheck) certCheck {
	return func(t *testing.T, cert *ssh.Certificate) {
		for _, check := range checks {
			check(t, cert)
		}
	}
}

func checkPrincipal(principals ...string) certCheck {
	return func(t *testing.T, cert *ssh.Certificate) {
		require.Equal(t, cert.ValidPrincipals, principals)
	}
}

func checkSignatureAlgorithm(algorithm string) certCheck {
	return func(t *testing.T, cert *ssh.Certificate) {
		require.Equal(t, cert.Signature.Format, algorithm)
	}
}

func checkExtension(key string, value string) certCheck {
	return func(t *testing.T, cert *ssh.Certificate) {
		require.Equal(t, cert.Extensions[key], value)
	}
}

func TestHandleRequest(t *testing.T) {
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ed25519Signer, err := ssh.NewSignerFromSigner(ed25519Key)
	require.NoError(t, err)

	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p256Signer, err := ssh.NewSignerFromSigner(p256Key)
	require.NoError(t, err)

	for _, c := range []struct {
		description     string
		allowedKeyTypes []string
		iamClient       iamiface.IAMAPI
		signer          ssh.Signer
		userArn         string
		host            string
		body            string
		responseChecks  responseCheck
		certChecks      certCheck
	}{
		{
			description:     "Valid ed25519",
			allowedKeyTypes: []string{"ssh-ed25519"},
			signer:          ed25519Signer,
			userArn:         "arn:aws:iam::12345:user/john-doe",
			host:            "test.local",
			body:            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOfreF0kMkdJ1ISFvPsucJ7X8UJ07rQV99hQGLYBuSV",
			responseChecks:  checkStatusCode(http.StatusOK),
			certChecks: certChecks(
				checkPrincipal("arn:aws:iam::12345:user/john-doe"),
				checkExtension("hallow-host@dc.cant.vote", "test.local"),
				checkSignatureAlgorithm(ssh.KeyAlgoED25519),
			),
		},
		{
			description:     "Valid ed25519, p256 signer",
			allowedKeyTypes: []string{"ssh-ed25519"},
			signer:          p256Signer,
			userArn:         "arn:aws:iam::12345:user/john-doe",
			host:            "test.local",
			body:            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOfreF0kMkdJ1ISFvPsucJ7X8UJ07rQV99hQGLYBuSV",
			responseChecks:  checkStatusCode(http.StatusOK),
			certChecks: certChecks(
				checkPrincipal("arn:aws:iam::12345:user/john-doe"),
				checkExtension("hallow-host@dc.cant.vote", "test.local"),
				checkSignatureAlgorithm(ssh.KeyAlgoECDSA256),
			),
		},
		{
			description:     "Assumed role with tags",
			allowedKeyTypes: []string{"ssh-ed25519"},
			iamClient: fakeIAMAPI{
				roleAdditionalPrincipals: map[string]string{
					"my-role": "additional-principal",
				},
			},
			signer:         ed25519Signer,
			userArn:        "arn:aws:sts::12345:assumed-role/my-role/comment",
			host:           "test.local",
			body:           "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOfreF0kMkdJ1ISFvPsucJ7X8UJ07rQV99hQGLYBuSV",
			responseChecks: checkStatusCode(http.StatusOK),
			certChecks: certChecks(
				checkPrincipal("arn:aws:sts::12345:assumed-role/my-role", "additional-principal"),
				checkExtension("hallow-host@dc.cant.vote", "test.local"),
				checkSignatureAlgorithm(ssh.KeyAlgoED25519),
			),
		},
		{
			description:     "Disallowed keyType",
			allowedKeyTypes: []string{"ssh-rsa"},
			signer:          ed25519Signer,
			userArn:         "arn:aws:iam::12345:user/john-doe",
			host:            "test.local",
			body:            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJOfreF0kMkdJ1ISFvPsucJ7X8UJ07rQV99hQGLYBuSV",
			responseChecks:  checkStatusCode(http.StatusBadRequest),
		},
		{
			description:    "Malformed public key",
			userArn:        "arn:aws:iam::12345:user/john-doe",
			signer:         ed25519Signer,
			host:           "test.local",
			body:           "not even remotely a key",
			responseChecks: checkStatusCode(http.StatusBadRequest),
		},
		{
			description:     "Small RSA key",
			allowedKeyTypes: []string{"ssh-rsa"},
			signer:          ed25519Signer,
			userArn:         "arn:aws:iam::12345:user/john-doe",
			host:            "test.local",
			body:            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC5OXmDKEHLVj7nTnYlO5dOdK0BO1XJasLSaz9H+Psj/V3DZeQyJZFkJzyByQXOZa7DN+WEkqaapFb7ttS90Bb+zQ5raeCl3GiRmAH8peHPiOn3Sp5G9QtLFNlYuVswdzYdONX0NTIhF//L7+fmL83fr6WzdnXKL8iSsxSCBKKS5Q==",
			responseChecks:  checkStatusCode(http.StatusBadRequest),
		},
	} {
		t.Run(c.description, func(t *testing.T) {
			requestEvent := events.APIGatewayProxyRequest{
				RequestContext: events.APIGatewayProxyRequestContext{
					Identity: events.APIGatewayRequestIdentity{
						UserArn: c.userArn,
					},
				},
				Headers: map[string]string{
					"Host": c.host,
				},
				Body: c.body,
			}

			config := config{
				iamClient:       c.iamClient,
				allowedKeyTypes: c.allowedKeyTypes,
				ca: CA{
					Rand:   rand.Reader,
					Signer: c.signer,
				},
			}
			response, err := config.handleRequest(context.Background(), requestEvent)
			require.NoError(t, err)
			if c.responseChecks != nil {
				c.responseChecks(t, response)
			}
			if c.certChecks != nil {
				key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.Body))
				require.NoError(t, err)
				c.certChecks(t, key.(*ssh.Certificate))
			}
		})
	}
}
