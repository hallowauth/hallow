package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
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

func (c *config) handleRequest(ctx context.Context, event events.APIGatewayProxyRequest) (string, error) {
	principal := event.RequestContext.Identity.UserArn
	publicKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(event.Body))
	if err != nil {
		log.Println(err)
		return "", err
	}
	if !stringSliceContains(publicKey.Type(), c.allowedKeyTypes) {
		return "", fmt.Errorf("Disallowed public key type: %s", publicKey.Type())
	}

	var b [8]byte
	if _, err := c.ca.Rand.Read(b[:]); err != nil {
		log.Println(err)
		return "", err
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

	sshCert, _, err := c.ca.SignAndParse(template)
	if err != nil {
		log.Println(err)
		return "", err
	}
	return fmt.Sprintf("%s %s\n", sshCert.Type(), base64.StdEncoding.EncodeToString(sshCert.Marshal())), nil
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
