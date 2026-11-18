package adapters

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"cryptographic/internal/application/ports"
	"errors"
	"fmt"
	"io"
	"os"
)

type Encrypt struct{}

func (Encrypt) GenerateEncryption(
	dek *ports.DEK,
	privateKey []byte,
	kid string,
) (*ports.Encrypted, error) {
	if dek == nil {
		return nil, errors.New("[ADAPTER][ENCRYPTION][ERROR] DEK cannot be nil")
	}

	if len(dek.PlainText) != 32 {
		return nil, errors.New("[ADAPTER][ENCRYPTION][ERROR] AES-256 requires a 32-byte DEK")
	}

	if len(dek.CipherTextBlob) == 0 {
		return nil, errors.New("[ADAPTER][ENCRYPTION][ERROR] encrypted DEK cannot be empty")
	}

	if len(privateKey) == 0 {
		return nil, errors.New("[ADAPTER][ENCRYPTION][ERROR] private key cannot be empty")
	}

	if kid == "" {
		return nil, errors.New("[ADAPTER][ENCRYPTION][ERROR] key ID cannot be empty")
	}

	block, err := aes.NewCipher(dek.PlainText)
	if err != nil {
		return nil, fmt.Errorf("[ADAPTER][ENCRYPTION][ERROR] create AES cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("[ADAPTER][ENCRYPTION][ERROR] create AES-GCM: %w", err)
	}

	nonce := make([]byte, aesgcm.NonceSize())

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("[ADAPTER][ENCRYPTION][ERROR] generate nonce: %w", err)
	}

	version := os.Getenv("SIGNING_KEY_VERSION")
	aad := []byte("foundation:signing-key:" + version + ":" + kid)

	encryptedPrivateKey := aesgcm.Seal(
		nil,
		nonce,
		privateKey,
		aad,
	)

	return &ports.Encrypted{
		EncryptedDek:        dek.CipherTextBlob,
		EncryptedPrivateKey: encryptedPrivateKey,
		Nonce:               nonce,
		Version:             version,
	}, nil
}
