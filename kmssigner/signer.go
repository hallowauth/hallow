package kmssigner

import (
	"context"
	"crypto"
	"crypto/x509"
	"io"

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
	signatureResponse, err := k.kmsapi.SignWithContext(context.TODO(), &kms.SignInput{
		KeyId:            aws.String(k.keyArn),
		Message:          digest,
		MessageType:      aws.String("DIGEST"),
		SigningAlgorithm: aws.String(cryptoHashToKmsHash[opts.HashFunc()]),
	})
	if err != nil {
		return nil, err
	}
	return signatureResponse.Signature, nil
}

// TODO: Fill in more hashes and take into account key type.
var cryptoHashToKmsHash = map[crypto.Hash]string{
	crypto.SHA256: kms.SigningAlgorithmSpecEcdsaSha256,
}
