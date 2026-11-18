package adapters

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"cryptographic/internal/application/ports"
)

func TestEncryptGenerateEncryptionRoundTrip(t *testing.T) {
	dek := &ports.DEK{
		PlainText:      []byte("01234567890123456789012345678901"),
		CipherTextBlob: []byte("kms-encrypted-dek"),
		KmsKeyId:       "alias/werant-rotation-key",
	}
	privateKey := []byte("private PKCS #8 material")
	kid := "019a92fe-5400-7abc-8000-000000000001"
	version := "v1"

	encrypted, err := CreateEncrypt(version).GenerateEncryption(dek, privateKey, kid)
	if err != nil {
		t.Fatalf("GenerateEncryption() error = %v", err)
	}

	if !bytes.Equal(encrypted.EncryptedDek, dek.CipherTextBlob) {
		t.Errorf("EncryptedDek = %q, want %q", encrypted.EncryptedDek, dek.CipherTextBlob)
	}
	if encrypted.Version != version {
		t.Errorf("Version = %q, want %q", encrypted.Version, version)
	}
	if bytes.Equal(encrypted.EncryptedPrivateKey, privateKey) {
		t.Error("encrypted private key matches plaintext")
	}

	block, err := aes.NewCipher(dek.PlainText)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}

	aad := []byte("foundation:signing-key:" + version + ":" + kid)
	decrypted, err := aesGCM.Open(nil, encrypted.Nonce, encrypted.EncryptedPrivateKey, aad)
	if err != nil {
		t.Fatalf("decrypt encrypted private key: %v", err)
	}
	if !bytes.Equal(decrypted, privateKey) {
		t.Errorf("decrypted private key = %q, want %q", decrypted, privateKey)
	}
}

func TestEncryptGenerateEncryptionBindsCiphertextToAAD(t *testing.T) {
	dek := &ports.DEK{
		PlainText:      []byte("01234567890123456789012345678901"),
		CipherTextBlob: []byte("kms-encrypted-dek"),
	}
	encrypted, err := CreateEncrypt("v1").GenerateEncryption(dek, []byte("private-key"), "expected-kid")
	if err != nil {
		t.Fatalf("GenerateEncryption() error = %v", err)
	}

	block, err := aes.NewCipher(dek.PlainText)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM() error = %v", err)
	}

	wrongAAD := []byte("foundation:signing-key:v1:different-kid")
	if _, err := aesGCM.Open(nil, encrypted.Nonce, encrypted.EncryptedPrivateKey, wrongAAD); err == nil {
		t.Fatal("decrypt with different kid succeeded, want authentication failure")
	}
}

func TestEncryptGenerateEncryptionValidatesInput(t *testing.T) {
	validDEK := &ports.DEK{
		PlainText:      []byte("01234567890123456789012345678901"),
		CipherTextBlob: []byte("kms-encrypted-dek"),
	}

	tests := []struct {
		name       string
		dek        *ports.DEK
		privateKey []byte
		kid        string
	}{
		{name: "nil DEK", dek: nil, privateKey: []byte("private"), kid: "kid"},
		{name: "invalid AES key size", dek: &ports.DEK{PlainText: []byte("short"), CipherTextBlob: []byte("encrypted")}, privateKey: []byte("private"), kid: "kid"},
		{name: "empty encrypted DEK", dek: &ports.DEK{PlainText: validDEK.PlainText}, privateKey: []byte("private"), kid: "kid"},
		{name: "empty private key", dek: validDEK, privateKey: nil, kid: "kid"},
		{name: "empty kid", dek: validDEK, privateKey: []byte("private"), kid: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CreateEncrypt("v1").GenerateEncryption(test.dek, test.privateKey, test.kid)
			if err == nil {
				t.Fatal("GenerateEncryption() error = nil, want validation error")
			}
		})
	}
}
