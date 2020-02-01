package kmssigner

import (
	"context"
	"fmt"
	"io"

	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
)

type kmsSigner struct {
	kmsapi *kms.KMS
	keyArn string
	pubKey crypto.PublicKey
}

func New(kmsapi *kms.KMS, keyArn string) (crypto.Signer, error) {
	pubKeyResponse, err := kmsapi.GetPublicKeyWithContext(context.TODO(), &kms.GetPublicKeyInput{
		KeyId: aws.String(keyArn),
	})
	if err != nil {
		return nil, err
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyResponse.PublicKey)
	if err != nil {
		return nil, err
	}

	return kmsSigner{
		kmsapi: kmsapi,
		keyArn: keyArn,
		pubKey: pubKey,
	}, nil
}

func (k kmsSigner) Public() crypto.PublicKey {
	return k.pubKey
}

func (k kmsSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signingAlgorithm, err := kmsSigningAlgorithm(k.pubKey, opts)
	if err != nil {
		return nil, err
	}

	signatureResponse, err := k.kmsapi.SignWithContext(context.TODO(), &kms.SignInput{
		KeyId:            aws.String(k.keyArn),
		Message:          digest,
		MessageType:      aws.String("DIGEST"),
		SigningAlgorithm: aws.String(signingAlgorithm),
	})
	if err != nil {
		return nil, err
	}
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
		// We currently only support PKCS1v1.5 because we're we're bad people
		// and feel bad about it.
		//
		// We may add a config bool (UsePSSPadding or something) to flip this
		// to PSS in the future, but for now, since most things expect
		// PKCS1v1.5, and people will be mad at us if we just, well, don't
		// support RSA at all.
		//
		// So, here we are.
		switch opts.HashFunc() {
		case crypto.SHA256:
			return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			return kms.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		}
	}

	return "", fmt.Errorf("hallow/kmsigner: unknown key algorithm")
}
