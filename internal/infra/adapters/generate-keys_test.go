package adapters

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/google/uuid"
)

func TestRSAKeysGenerateRSAKeys(t *testing.T) {
	keys, err := (RSAKeys{}).GenerateRSAKeys()
	if err != nil {
		t.Fatalf("GenerateRSAKeys() error = %v", err)
	}

	parsedID, err := uuid.Parse(keys.Kid)
	if err != nil {
		t.Fatalf("generated kid %q is not a UUID: %v", keys.Kid, err)
	}
	if parsedID.Version() != 7 {
		t.Errorf("kid UUID version = %d, want 7", parsedID.Version())
	}

	var jwk JWK
	if err := json.Unmarshal(keys.PublicKey, &jwk); err != nil {
		t.Fatalf("unmarshal public JWK: %v", err)
	}

	if jwk.Kty != "RSA" {
		t.Errorf("JWK kty = %q, want RSA", jwk.Kty)
	}
	if jwk.Alg != "RS256" {
		t.Errorf("JWK alg = %q, want RS256", jwk.Alg)
	}
	if jwk.Use != "sig" {
		t.Errorf("JWK use = %q, want sig", jwk.Use)
	}
	if jwk.Kid != keys.Kid {
		t.Errorf("JWK kid = %q, generated kid = %q", jwk.Kid, keys.Kid)
	}
	if jwk.E != "AQAB" {
		t.Errorf("JWK exponent = %q, want AQAB", jwk.E)
	}

	privateMaterial, err := x509.ParsePKCS8PrivateKey(keys.PrivateKey)
	if err != nil {
		t.Fatalf("parse PKCS #8 private key: %v", err)
	}

	privateKey, ok := privateMaterial.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T, want *rsa.PrivateKey", privateMaterial)
	}
	if privateKey.N.BitLen() != 2048 {
		t.Errorf("RSA modulus bit length = %d, want 2048", privateKey.N.BitLen())
	}

	modulusBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("decode JWK modulus: %v", err)
	}
	if new(big.Int).SetBytes(modulusBytes).Cmp(privateKey.N) != 0 {
		t.Error("JWK modulus does not match generated private key")
	}
}

func TestIdGeneratorGeneratesUUIDv7(t *testing.T) {
	id, err := (IdGenerator{}).IdGenerator()
	if err != nil {
		t.Fatalf("IdGenerator() error = %v", err)
	}

	parsed, err := uuid.Parse(*id)
	if err != nil {
		t.Fatalf("generated ID %q is not a UUID: %v", *id, err)
	}
	if parsed.Version() != 7 {
		t.Errorf("UUID version = %d, want 7", parsed.Version())
	}
}
