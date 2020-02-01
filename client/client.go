package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ScaleFT/sshkeys"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/aws/signer/v4"
)

// GenerateKeyAndObtainCertificate will generate an SSH private key, obtain a
// short-lived certificate for it from Hallow, and then return the
// (privateKey, certificate, error).
func GenerateKeyAndObainCertificate(ctx context.Context, sess *session.Session, httpClient *http.Client, hallowEndpoint string, comment string) ([]byte, []byte, error) {
	pubKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, nil, err
	}

	signer := v4.NewSigner(sess.Config.Credentials)

	requestBody := fmt.Sprintf("%s %s %s\n", sshPubKey.Type(), base64.StdEncoding.EncodeToString(sshPubKey.Marshal()), comment)
	req, err := http.NewRequest(
		http.MethodPut,
		hallowEndpoint,
		strings.NewReader(requestBody),
	)
	if err != nil {
		return nil, nil, err
	}

	header, err := signer.Presign(
		req,
		strings.NewReader(requestBody),
		"execute-api",
		*sess.Config.Region,
		2*time.Second,
		time.Now(),
	)
	if err != nil {
		return nil, nil, err
	}

	req.Header = header
	req.Body = ioutil.NopCloser(strings.NewReader(requestBody))
	req = req.WithContext(ctx)

	response, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		responseBody, _ := ioutil.ReadAll(response.Body)
		return nil, nil, fmt.Errorf("HTTP error from hallow. Status=%d: %s", response.StatusCode, responseBody)
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, nil, err
	}

	sshPrivateKey, err := sshkeys.Marshal(privateKey, &sshkeys.MarshalOptions{
		Format: sshkeys.FormatOpenSSHv1,
	})
	if err != nil {
		return nil, nil, err
	}

	return sshPrivateKey, responseBody, nil
}
