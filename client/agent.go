package client

import (
	"context"
	"crypto"
	log "github.com/sirupsen/logrus"
	"net/url"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// GetOrGenerateFromAgent will either fetch the first (by ssh-agent ordering)
// valid ssh Certificate issued by our configured upstream, or generate a new
// private key, request a Certificate, and add that Certificate to the running
// agent.
//
// This will allow the caller to repeatedly call this function (for instance,
// on every ssh invocation), and not flood the agent with new private key
// material.
//
// This function will never reuse existing private key material when getting
// a new Certificate, a new key will always be created.
//
// Keys added to the agent will have their LifetimeSecs set as appropriate
// to clean the keyring when the key expires.
func (c Client) GetOrGenerateFromAgent(
	ctx context.Context,
	agentClient agent.Agent,
	keyType KeyType,
	keyId string,
) (ssh.PublicKey, error) {
	certs, err := c.ListCertificatesFromAgent(agentClient)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Warn("failed to fetch certificates from agent")
		return nil, err
	}

	// Maybe not the best semantics.
	if len(certs) > 0 {
		cert := certs[0]
		logWithCertificate(cert).Debug("Using existing Certificate")
		return certs[0], nil
	}

	log.Trace("requesting a cert from hallow")
	priv, pub, err := c.GenerateAndRequestCertificate(ctx, keyType, keyId)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err,
		}).Warn("failed to generate and request from hallow")
		return nil, err
	}

	logWithCertificate(pub.(*ssh.Certificate)).Debug("Got a new Certificate")

	return pub, addCertificateToAgent(
		agentClient,
		priv,
		pub.(*ssh.Certificate),
		keyId,
	)
}

// Handle the actual addition of the key to the agent.
func addCertificateToAgent(
	agentClient agent.Agent,
	privKey crypto.Signer,
	cert *ssh.Certificate,
	keyId string,
) error {
	lifetime := int64(cert.ValidBefore) - time.Now().Unix()

	l := logWithCertificate(cert).WithFields(log.Fields{
		"agent.lifetime_secs": lifetime,
	})

	if err := agentClient.Add(agent.AddedKey{
		PrivateKey:   privKey,
		Certificate:  cert,
		LifetimeSecs: uint32(lifetime),
		Comment:      keyId,
	}); err != nil {
		l.WithFields(log.Fields{
			"error": err,
		}).Warn("failed to add Certifciate to agent")
		return err
	}

	l.Trace("certificate added to ssh-agent")
	return nil
}

// ListCertificatesFromAgent will find all active ssh.Certificate entries in the
// connected ssh agent which were issued by the endpoint the Client is
// configured to talk to.
func (c Client) ListCertificatesFromAgent(
	agentClient agent.Agent,
) ([]*ssh.Certificate, error) {
	uri, err := url.Parse(c.endpoint)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("failed to parse endpoint")
		return nil, err
	}

	now := time.Now()

	agentKeys, err := agentClient.List()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("failed to list keys")
		return nil, err
	}

	ret := []*ssh.Certificate{}

	for _, agentKey := range agentKeys {
		pubKey, err := ssh.ParsePublicKey(agentKey.Marshal())
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
			}).Warn("failed to parse key from agent; skipping")
			continue
		}

		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			// not a Certificate
			continue
		}

		l := logWithCertificate(cert)

		host, ok := cert.Extensions["hallow-host@dc.cant.vote"]
		if !ok {
			l.Trace("not a hallow certificate, moving on")
			// not a hallowed Certificate
			continue
		}

		if host != uri.Host {
			l.Trace("not a hallow certificate issued by our target host, moving on")
			// not our host
			continue
		}

		validBefore := time.Unix(int64(cert.ValidBefore), 0)
		validAfter := time.Unix(int64(cert.ValidAfter), 0)

		if now.After(validBefore) && now.Before(validAfter) {
			// We're either before or after the validity duration of
			// this Certificate.
			l.Info("ignoring expired cert!")
			continue
		}

		l.Trace("valid certificate found")
		ret = append(ret, cert)
	}

	return ret, nil
}
