package services

import (
	"context"
	"cryptographic/internal/application/ports"
	"cryptographic/internal/domain/entities"
)

type CreateSigningKeyConstructorDep struct {
	ports.RSAKeys
	ports.Encrypt
	ports.Clock
	ports.KMS
	ports.Id
	Ctx context.Context
}

func CreateSigningKey(dep CreateSigningKeyConstructorDep) (entities.SigningKey, error) {
	keys, err := dep.RSAKeys.GenerateRSAKeys()
	if err != nil {
		return entities.SigningKey{}, err
	}

	dek, err := dep.KMS.GenerateDataEncryptionKey(dep.Ctx)
	if err != nil {
		return entities.SigningKey{}, err
	}

	encrypted, err := dep.Encrypt.GenerateEncryption(dek, keys.PrivateKey, keys.Kid)
	if err != nil {
		return entities.SigningKey{}, err
	}

	id, err := dep.Id.IdGenerator()
	if err != nil {
		return entities.SigningKey{}, err
	}

	now := dep.Clock.NowISO8601()

	return entities.SigningKey{
		Id:                  *id,
		Kid:                 keys.Kid,
		Algorithm:           "RS256",
		Status:              "pending",
		Version:             encrypted.Version,
		PublicJwk:           keys.PublicKey,
		EncryptedPrivateKey: encrypted.EncryptedPrivateKey,
		EncryptedDek:        encrypted.EncryptedDek,
		Nonce:               encrypted.Nonce,
		KmsKeyId:            dek.KmsKeyId,
		CreatedAt:           now,
		UpdatedAt:           now,
		ActivatedAt:         nil,
		DeactivatedAt:       nil,
		RetiredAt:           nil,
	}, nil
}
