package client

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
)

// Client is an encapsulation of the configuration and state required to request
// a new ssh certificate from the Hallow server.
type Client struct {
	session    *session.Session
	endpoint   string
	httpClient *http.Client
}

// New creates a new Client object with the configured AWS session, HTTP
// Client, and the Hallow API endpoint.
func New(sess *session.Session, endpoint string) Client {
	return NewWithHTTPClient(sess, http.DefaultClient, endpoint)
}

func NewWithHTTPClient(sess *session.Session, client *http.Client, endpoint string) Client {
	return Client{
		session:    sess,
		endpoint:   endpoint,
		httpClient: client,
	}
}

// We need to implement keyToString because `ssh.MarshalAuthorizedKey` will
// not include the Comment, since the `ssh.PublicKey` struct doesn't store
// the comment at all. This could be inprovide by calling ssh.MarshalAuthorizedKey
// and slicing the string, but like, that seems worse than just base64ing it.
func keyToString(pubKey ssh.PublicKey, comment string) string {
	return fmt.Sprintf(
		"%s %s %s\n",
		pubKey.Type(),
		base64.StdEncoding.EncodeToString(pubKey.Marshal()),
		comment,
	)
}

// GenerateAndRequestCertificate will create a very opinionated private key,
// and return the private key handle, the public key (signed by Hallow), and
// any error conditions that were hit during execution.
func (c Client) GenerateAndRequestCertificate(
	ctx context.Context,
	keyType KeyType,
	comment string,
) (crypto.Signer, ssh.PublicKey, error) {
	l := log.WithFields(log.Fields{
		"hallow.public_key.comment": comment,
	})

	privKey, pubKey, err := generateKey(rand.Reader, keyType)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Fatal("Can't generate key")
		return nil, nil, err
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Fatal("Can't create ssh Public Key")
		return nil, nil, err
	}

	l = l.WithFields(log.Fields{"hallow.public_key.type": sshPubKey.Type()})

	sshPubKey, err = c.RequestCertificate(
		ctx,
		sshPubKey,
		comment,
	)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Fatal("Failed to sign key")
		return nil, nil, err
	}

	return privKey, sshPubKey, nil

}

// RequestCertificate will request that the CA sign our Public Key. This
// function will return the parsed ssh.PublicKey (which is of type
// ssh.Certificate), as well as the stringified version of that Certificate
// in a format ssh will understand as a public key.
func (c Client) RequestCertificate(
	ctx context.Context,
	pubKey ssh.PublicKey,
	comment string,
) (ssh.PublicKey, error) {
	l := log.WithFields(log.Fields{
		"hallow.public_key.comment": comment,
		"hallow.public_key.type":    pubKey.Type(),
		"hallow.endpoint":           c.endpoint,
	})

	signer := v4.NewSigner(c.session.Config.Credentials)
	requestBody := keyToString(pubKey, comment)
	req, err := http.NewRequest(
		http.MethodPut,
		c.endpoint,
		strings.NewReader(requestBody),
	)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Fatal("Failed to create Request")
		return nil, err
	}
	header, err := signer.Presign(
		req,
		strings.NewReader(requestBody),
		"execute-api",
		*c.session.Config.Region,
		2*time.Second,
		time.Now(),
	)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Fatal("Failed to Presign request")
		return nil, err
	}

	req.Header = header
	req.Body = ioutil.NopCloser(strings.NewReader(requestBody))
	req = req.WithContext(ctx)

	l.Trace("Requesting SSH Certificate")
	response, err := c.httpClient.Do(req)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Fatal("Failed to call endpoint")
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		responseBody, _ := ioutil.ReadAll(response.Body)
		err := fmt.Errorf(
			"hallow/client: HTTP error from hallow. Status=%d: %s",
			response.StatusCode,
			responseBody,
		)
		l.WithFields(log.Fields{"error": err}).Fatal("Got a non-200 exit code")
		return nil, err
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Fatal("Can't read HTTP Body")
		return nil, err
	}

	pubKey, _, _, _, err = ssh.ParseAuthorizedKey(responseBody)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Fatal("Failed to re-parse SSH pubkey")
		return nil, err
	}

	logWithCertificate(pubKey.(*ssh.Certificate)).Debug("Sucessfully got an SSH Certificate")
	return pubKey, nil
}
