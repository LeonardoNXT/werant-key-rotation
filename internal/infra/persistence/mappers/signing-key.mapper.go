package mappers

import (
	"time"

	"cryptographic/internal/domain/entities"
	"cryptographic/internal/infra/persistence/models"
)

func SigningKeyToORM(signingKeyEntity entities.SigningKey) (*models.SigningKey, error) {

	createdAt, err := time.Parse(time.RFC3339, signingKeyEntity.CreatedAt)
	if err != nil {
		return nil, err
	}

	updatedAt, err := time.Parse(time.RFC3339, signingKeyEntity.UpdatedAt)
	if err != nil {
		return nil, err
	}

	return &models.SigningKey{
		Id:                  signingKeyEntity.Id,
		Kid:                 signingKeyEntity.Kid,
		Algorithm:           signingKeyEntity.Algorithm,
		Status:              signingKeyEntity.Status,
		Version:             signingKeyEntity.Version,
		PublicJwk:           signingKeyEntity.PublicJwk,
		EncryptedDek:        signingKeyEntity.EncryptedDek,
		EncryptedPrivateKey: signingKeyEntity.EncryptedPrivateKey,
		Nonce:               signingKeyEntity.Nonce,
		KmsKeyId:            signingKeyEntity.KmsKeyId,

		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
		ActivatedAt:   parseTimePtr(signingKeyEntity.ActivatedAt),
		DeactivatedAt: parseTimePtr(signingKeyEntity.DeactivatedAt),
		RetiredAt:     parseTimePtr(signingKeyEntity.RetiredAt),
	}, nil
}

func SigningKeyToEntity(signingKeyModel models.SigningKey) (*entities.SigningKey, error) {
	return &entities.SigningKey{
		Id:                  signingKeyModel.Id,
		Kid:                 signingKeyModel.Kid,
		Algorithm:           signingKeyModel.Algorithm,
		Status:              signingKeyModel.Status,
		Version:             signingKeyModel.Version,
		PublicJwk:           signingKeyModel.PublicJwk,
		EncryptedDek:        signingKeyModel.EncryptedDek,
		EncryptedPrivateKey: signingKeyModel.EncryptedPrivateKey,
		Nonce:               signingKeyModel.Nonce,
		KmsKeyId:            signingKeyModel.KmsKeyId,

		CreatedAt:     signingKeyModel.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     signingKeyModel.UpdatedAt.Format(time.RFC3339),
		ActivatedAt:   formatTimePtr(signingKeyModel.ActivatedAt),
		DeactivatedAt: formatTimePtr(signingKeyModel.DeactivatedAt),
		RetiredAt:     formatTimePtr(signingKeyModel.RetiredAt),
	}, nil
}

func parseTimePtr(dateStr *string) *time.Time {
	if dateStr == nil || *dateStr == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *dateStr)
	if err != nil {
		return nil
	}
	return &t
}

func formatTimePtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	formatted := t.UTC().Format(time.RFC3339)
	return &formatted
}
