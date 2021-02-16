package main

import (
	"crypto"
	"io"

	"golang.org/x/crypto/ssh"
)

type SignerChooser interface {
	Choose(APIGatewayContext) (crypto.Signer, error)
}

// CA is an implementation of the OpenSSH Certificate Authority.
//
// This encapsulates the signing code, as well as the RNG source to be used
// for signing operations. This contains no logic regarding certificate policy
// or principal policy, rather, it's just the underlying code to do the
// signing.
type CA struct {
	// RNG source. This should almost always be crypto/rand.Reader, unless
	// your underlying crypto.Signer has an on-chip RNG, in which case this
	// may be set to something like `nil`.
	Rand io.Reader

	// Interface to choose which signer to use based on request information
	signerChooser SignerChooser
}

// Sign an SSH Certificate template (with `Key` set), and return the
// certificate.
func (s CA) Sign(template ssh.Certificate, context APIGatewayContext) (*ssh.Certificate, error) {
	signer, err := s.signerChooser.Choose(context)
	if err != nil {
		return nil, err
	}

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, err
	}

	return CreateCertificate(
		s.Rand,
		template,
		sshSigner.PublicKey(),
		template.Key,
		sshSigner,
	)
}

// CreateCertificate will create an SSH Certificate with an API that looks
// similar to the x509.CreateCertificate signature for ease of use.
func CreateCertificate(
	rand io.Reader,
	template ssh.Certificate,
	parent ssh.PublicKey,
	pub ssh.PublicKey,
	priv ssh.Signer,
) (*ssh.Certificate, error) {
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          template.Serial,
		CertType:        template.CertType,
		KeyId:           template.KeyId,
		ValidPrincipals: template.ValidPrincipals,
		ValidAfter:      template.ValidAfter,
		ValidBefore:     template.ValidBefore,
		SignatureKey:    parent,
		Permissions: ssh.Permissions{
			CriticalOptions: template.CriticalOptions,
			Extensions:      template.Extensions,
		},
	}

	err := cert.SignCert(rand, priv)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
