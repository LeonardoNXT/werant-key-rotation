package mappers

import (
	"reflect"
	"testing"
	"time"

	"cryptographic/internal/domain/entities"
)

func TestSigningKeyMapperRoundTrip(t *testing.T) {
	activatedAt := "2026-11-17T20:05:00Z"
	deactivatedAt := "2026-11-17T20:15:00Z"
	retiredAt := "2026-11-17T20:25:00Z"

	original := entities.SigningKey{
		Id:                  "019a92fe-5400-7abc-8000-000000000001",
		Kid:                 "019a92fe-5400-7abc-8000-000000000002",
		Algorithm:           "RS256",
		Status:              "retired",
		Version:             "v1",
		PublicJwk:           []byte(`{"kty":"RSA"}`),
		EncryptedPrivateKey: []byte("encrypted-private-key"),
		EncryptedDek:        []byte("encrypted-dek"),
		Nonce:               []byte("0123456789ab"),
		KmsKeyId:            "alias/werant-rotation-key",
		CreatedAt:           "2026-11-17T20:00:00Z",
		UpdatedAt:           "2026-11-17T20:25:00Z",
		ActivatedAt:         &activatedAt,
		DeactivatedAt:       &deactivatedAt,
		RetiredAt:           &retiredAt,
	}

	model, err := SigningKeyToORM(original)
	if err != nil {
		t.Fatalf("SigningKeyToORM() error = %v", err)
	}

	if model.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", model.CreatedAt.Location())
	}

	result, err := SigningKeyToEntity(*model)
	if err != nil {
		t.Fatalf("SigningKeyToEntity() error = %v", err)
	}

	if !reflect.DeepEqual(*result, original) {
		t.Errorf("mapper round trip mismatch\n got: %#v\nwant: %#v", *result, original)
	}
}

func TestSigningKeyToORMPreservesNilLifecycleTimestamps(t *testing.T) {
	model, err := SigningKeyToORM(entities.SigningKey{
		CreatedAt: "2026-11-17T20:00:00Z",
		UpdatedAt: "2026-11-17T20:00:00Z",
	})
	if err != nil {
		t.Fatalf("SigningKeyToORM() error = %v", err)
	}

	if model.ActivatedAt != nil || model.DeactivatedAt != nil || model.RetiredAt != nil {
		t.Errorf("lifecycle timestamps = (%v, %v, %v), want nil", model.ActivatedAt, model.DeactivatedAt, model.RetiredAt)
	}
}

func TestSigningKeyToORMRejectsInvalidCreatedAt(t *testing.T) {
	_, err := SigningKeyToORM(entities.SigningKey{
		CreatedAt: "not-a-timestamp",
		UpdatedAt: "2026-11-17T20:00:00Z",
	})
	if err == nil {
		t.Fatal("SigningKeyToORM() error = nil, want invalid CreatedAt error")
	}
}

func TestSigningKeyToORMRejectsInvalidUpdatedAt(t *testing.T) {
	_, err := SigningKeyToORM(entities.SigningKey{
		CreatedAt: "2026-11-17T20:00:00Z",
		UpdatedAt: "not-a-timestamp",
	})
	if err == nil {
		t.Fatal("SigningKeyToORM() error = nil, want invalid UpdatedAt error")
	}
}
