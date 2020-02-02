package client

import (
	"context"
	// "crypto/ed25519"
	// "crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	// "github.com/ScaleFT/sshkeys"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
)

type Client struct {
	session    *session.Session
	endpoint   string
	httpClient *http.Client
}

func New(sess *session.Session, client *http.Client, endpoint string) Client {
	return Client{
		session:    sess,
		endpoint:   endpoint,
		httpClient: client,
	}
}

func keyToString(pubKey ssh.PublicKey, comment string) string {
	return fmt.Sprintf(
		"%s %s %s\n",
		pubKey.Type(),
		base64.StdEncoding.EncodeToString(pubKey.Marshal()),
		comment,
	)
}

// RequestCertificate will request that the CA sign our Public Key. This
// function will return the parsed ssh.PublicKey (which is of type
// ssh.Certificate), as well as the stringified version of that Certificate
// in a format ssh will understand as a public key.
func (c Client) RequestCertificate(
	ctx context.Context,
	pubKey ssh.PublicKey,
	comment string,
) (ssh.PublicKey, string, error) {
	signer := v4.NewSigner(c.session.Config.Credentials)
	requestBody := keyToString(pubKey, comment)
	req, err := http.NewRequest(
		http.MethodPut,
		c.endpoint,
		strings.NewReader(requestBody),
	)
	if err != nil {
		return nil, "", err
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
		return nil, "", err
	}

	req.Header = header
	req.Body = ioutil.NopCloser(strings.NewReader(requestBody))
	req = req.WithContext(ctx)

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		responseBody, _ := ioutil.ReadAll(response.Body)
		return nil, "", fmt.Errorf(
			"HTTP error from hallow. Status=%d: %s",
			response.StatusCode,
			responseBody,
		)
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, "", err
	}

	pubKey, err = ssh.ParsePublicKey(responseBody)
	if err != nil {
		return nil, "", err
	}

	return pubKey, keyToString(pubKey, comment), nil
}

// // GenerateKeyAndObtainCertificate will generate an SSH private key, obtain a
// // short-lived certificate for it from Hallow, and then return the
// // (privateKey, certificate, error).
// func GenerateKeyAndObainCertificate(ctx context.Context, sess *session.Session, httpClient *http.Client, hallowEndpoint string, comment string) ([]byte, []byte, error) {
// 	pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	pubKey, err := ssh.NewPublicKey(pubKey)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	signer := v4.NewSigner(sess.Config.Credentials)
//
// 	requestBody := fmt.Sprintf("%s %s %s\n", pubKey.Type(), base64.StdEncoding.EncodeToString(pubKey.Marshal()), comment)
// 	req, err := http.NewRequest(
// 		http.MethodPut,
// 		hallowEndpoint,
// 		strings.NewReader(requestBody),
// 	)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	header, err := signer.Presign(
// 		req,
// 		strings.NewReader(requestBody),
// 		"execute-api",
// 		*sess.Config.Region,
// 		2*time.Second,
// 		time.Now(),
// 	)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	req.Header = header
// 	req.Body = ioutil.NopCloser(strings.NewReader(requestBody))
// 	req = req.WithContext(ctx)
//
// 	response, err := httpClient.Do(req)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	defer response.Body.Close()
// 	if response.StatusCode != http.StatusOK {
// 		responseBody, _ := ioutil.ReadAll(response.Body)
// 		return nil, nil, fmt.Errorf("HTTP error from hallow. Status=%d: %s", response.StatusCode, responseBody)
// 	}
//
// 	responseBody, err := ioutil.ReadAll(response.Body)
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	sshPrivateKey, err := sshkeys.Marshal(privateKey, &sshkeys.MarshalOptions{
// 		Format: sshkeys.FormatOpenSSHv1,
// 	})
// 	if err != nil {
// 		return nil, nil, err
// 	}
//
// 	return sshPrivateKey, responseBody, nil
// }
