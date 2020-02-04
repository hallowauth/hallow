package main

import (
	"crypto"
	"io"

	"golang.org/x/crypto/ssh"
)

// Implementation of the OpenSSH Certificate Authority.
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

	// Wrapped `crypto.Signer` to preform OpenSSH CA operations.
	Signer ssh.Signer
}

// Sign an SSH Certificate template (with `Key` set), and return the base64
// encoded ssh key entry (something like `ssh-*-cert`) that the user can
// import.
func (s CA) Sign(template ssh.Certificate) ([]byte, error) {
	return CreateCertificate(
		s.Rand,
		template,
		s.Signer.PublicKey(),
		template.Key,
		s.Signer,
	)
}

//
func (s CA) SignAndParse(template ssh.Certificate) (ssh.PublicKey, []byte, error) {
	bytes, err := s.Sign(template)
	if err != nil {
		return nil, nil, err
	}
	pubKey, err := ssh.ParsePublicKey(bytes)
	if err != nil {
		return nil, nil, err
	}
	return pubKey, bytes, nil
}

// Create a new SSH Certificate Authority to sign ssh public keys.
func New(rand io.Reader, priv crypto.Signer) (*CA, error) {
	signer, err := ssh.NewSignerFromSigner(priv)
	if err != nil {
		return nil, err
	}

	return &CA{
		Rand:   rand,
		Signer: signer,
	}, nil
}

// Create a Certificate. This signature looks similar to the
// x509.CreateCertificate signature for ease of use.
func CreateCertificate(
	rand io.Reader,
	template ssh.Certificate,
	parent ssh.PublicKey,
	pub ssh.PublicKey,
	priv ssh.Signer,
) ([]byte, error) {
	cert := ssh.Certificate{
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

	return cert.Marshal(), nil
}
