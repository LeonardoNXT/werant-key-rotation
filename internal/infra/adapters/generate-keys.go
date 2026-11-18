package adapters

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"cryptographic/internal/application/ports"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/google/uuid"
)

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	E   string `json:"e"`
	N   string `json:"n"`
}

type RSAKeys struct{}

func (RSAKeys) GenerateRSAKeys() (*ports.Keys, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("[ADAPTER][GENERATE-KEYS][ERROR] generate key ID: %w", err)
	}

	kid := id.String()
	key, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return nil, fmt.Errorf("[ADAPTER][GENERATE-KEYS][ERROR] generate RSA key: %w", err)
	}

	privateKey, err := x509.MarshalPKCS8PrivateKey(key)

	if err != nil {
		return nil, fmt.Errorf("[ADAPTER][GENERATE-KEYS][ERROR] marshal private key: %w", err)
	}

	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())

	jwk := JWK{
		Kty: "RSA",
		Alg: "RS256",
		Kid: kid,
		Use: "sig",
		E:   e,
		N:   n,
	}

	publicKey, err := json.Marshal(jwk)

	if err != nil {
		return nil, fmt.Errorf("[ADAPTER][GENERATE-KEYS][ERROR] marshal public JWK: %w", err)
	}

	return &ports.Keys{
		Kid:        kid,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}
