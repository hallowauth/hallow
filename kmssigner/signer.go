package kmssigner

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"

	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// kmsSigner is the internal bit of state used to create a crypto.Signer.
//
// This has no exported functions or params besides the signer interface,
// so this type was not exported.
type kmsSigner struct {
	kmsapi kmsiface.KMSAPI
	keyArn string
	pubKey crypto.PublicKey
	entry  *log.Entry
}

// New will create a new KMS Signer.
//
// The returned crypto.Signer will, when asked to sign, invoke the KMS to
// Sign the requested digest without holding the private key in memory at
// any time.
//
// When New is invoked, New will fetch the PublicKey from the KMS, and
// create a crypto.Signer that's able to preform the signing operations
// using the corresponding KMS private key.
//
// The returned crypto.Signer is an internal type, and contains no
// methods or exported fields beyond those required from the crypto.Signer
// interface.
func New(kmsapi kmsiface.KMSAPI, keyArn string) (crypto.Signer, error) {
	l := log.WithFields(log.Fields{
		"kmssigner.kms.key_arn": keyArn,
	})

	if len(keyArn) == 0 {
		l.Warn("The provided keyArn is empty!")
		return nil, fmt.Errorf("hallow/kmssigner: keyArn is an empty string")
	}

	pubKeyResponse, err := kmsapi.GetPublicKeyWithContext(
		context.TODO(),
		&kms.GetPublicKeyInput{
			KeyId: aws.String(keyArn),
		},
	)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Warn("Failed to get the Public Key")
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubKeyResponse.PublicKey)
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Warn("Failed to parse the PublicKey")
		return nil, err
	}

	return kmsSigner{
		kmsapi: kmsapi,
		keyArn: keyArn,
		pubKey: pubKey,
		entry:  l,
	}, nil
}

// Public will return the Public Key that this Signer will sign for.
func (k kmsSigner) Public() crypto.PublicKey {
	return k.pubKey
}

// Sign will, well, sign things.
func (k kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signingAlgorithm, err := kmsSigningAlgorithm(k.pubKey, opts)
	if err != nil {
		k.entry.WithFields(log.Fields{"error": err}).Warn("failed to get signature algorithm")
		return nil, err
	}

	l := k.entry.WithFields(log.Fields{
		"kmssigner.kms.signing_algorithm": signingAlgorithm,
		"request.digest":                  fmt.Sprintf("%x", digest),
	})

	signatureResponse, err := k.kmsapi.SignWithContext(context.TODO(), &kms.SignInput{
		KeyId:            aws.String(k.keyArn),
		Message:          digest,
		MessageType:      aws.String("DIGEST"),
		SigningAlgorithm: aws.String(signingAlgorithm),
	})
	if err != nil {
		l.WithFields(log.Fields{"error": err}).Warn("kms api call returned an error")
		return nil, err
	}
	l.Debug("sucessfully signed via kms")
	return signatureResponse.Signature, nil
}

// Given a public key and the signature options, return the right string to
// send to KMS so that we get a valid signature out.
func kmsSigningAlgorithm(pub crypto.PublicKey, opts crypto.SignerOpts) (string, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		switch opts.HashFunc() {
		case crypto.SHA256:
			return kms.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return kms.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return kms.SigningAlgorithmSpecEcdsaSha512, nil
		default:
			return "", fmt.Errorf("hallow/kmssigner: unknown hash algorithm for use with ECDSA")
		}
	case *rsa.PublicKey:
		// If the opts we're passed is a PSSOptions, sign with PSS,
		// otherwise fallback to PKCS1v1.5
		if _, ok := opts.(*rsa.PSSOptions); ok {
			// We don't handle SaltLength ATM...
			switch opts.HashFunc() {
			case crypto.SHA256:
				return kms.SigningAlgorithmSpecRsassaPssSha256, nil
			case crypto.SHA384:
				return kms.SigningAlgorithmSpecRsassaPssSha384, nil
			case crypto.SHA512:
				return kms.SigningAlgorithmSpecRsassaPssSha512, nil
			default:
				return "", fmt.Errorf("hallow/kmssigner: unknown hash algorithm for use with RSA")
			}
		}
		switch opts.HashFunc() {
		case crypto.SHA256:
			return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		default:
			return "", fmt.Errorf("hallow/kmssigner: unknown hash algorithm for use with RSA")
		}
	}

	return "", fmt.Errorf("hallow/kmsigner: unknown key algorithm")
}
