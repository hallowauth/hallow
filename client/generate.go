package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"
)

type KeyType uint8

const (
	KeyTypeECDSAP256 KeyType = iota
	KeyTypeECDSAP384
	KeyTypeECDSAP521
	KeyTypeED25519
	KeyTypeRSA2048
	KeyTypeRSA4096
)

// Generate a key of the given Key Type.
//
//
func generateKey(rand io.Reader, keyType KeyType) (crypto.Signer, crypto.PublicKey, error) {
	switch keyType {
	case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521:
		var curve elliptic.Curve
		switch keyType {
		case KeyTypeECDSAP256:
			curve = elliptic.P256()
		case KeyTypeECDSAP384:
			curve = elliptic.P384()
		case KeyTypeECDSAP521:
			curve = elliptic.P521()
		}
		privKey, err := ecdsa.GenerateKey(curve, rand)
		if err != nil {
			return nil, nil, err
		}
		return privKey, privKey.Public(), nil
	case KeyTypeRSA2048, KeyTypeRSA4096:
		var size int = 0
		switch keyType {
		case KeyTypeRSA2048:
			size = 2048
		case KeyTypeRSA4096:
			size = 4096
		}
		privKey, err := rsa.GenerateKey(rand, size)
		if err != nil {
			return nil, nil, err
		}
		return privKey, privKey.Public(), nil
	case KeyTypeED25519:
		pubKey, privKey, err := ed25519.GenerateKey(rand)
		return privKey, pubKey, err
	default:
		return nil, nil, fmt.Errorf("hallow/client: unknown key type: %x", keyType)
	}
}
