package services

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"cryptographic/internal/application/ports"
	"cryptographic/internal/domain/entities"
)

type rsaKeysStub struct {
	keys *ports.Keys
	err  error
}

func (stub rsaKeysStub) GenerateRSAKeys() (*ports.Keys, error) {
	return stub.keys, stub.err
}

type kmsStub struct {
	dek *ports.DEK
	err error
}

func (stub kmsStub) GenerateDataEncryptionKey(context.Context) (*ports.DEK, error) {
	return stub.dek, stub.err
}

type encryptStub struct {
	encrypted *ports.Encrypted
	err       error
	received  *encryptCall
}

type encryptCall struct {
	dek        *ports.DEK
	privateKey []byte
	kid        string
}

func (stub encryptStub) GenerateEncryption(dek *ports.DEK, privateKey []byte, kid string) (*ports.Encrypted, error) {
	if stub.received != nil {
		stub.received.dek = dek
		stub.received.privateKey = privateKey
		stub.received.kid = kid
	}
	return stub.encrypted, stub.err
}

type clockStub struct {
	now string
}

func (stub clockStub) NowISO8601() string {
	return stub.now
}

type idStub struct {
	id  *string
	err error
}

func (stub idStub) IdGenerator() (*string, error) {
	return stub.id, stub.err
}

func TestCreateSigningKey(t *testing.T) {
	id := "019a92fe-5400-7abc-8000-000000000001"
	dek := &ports.DEK{
		PlainText:      []byte("01234567890123456789012345678901"),
		CipherTextBlob: []byte("wrapped-dek"),
		KmsKeyId:       "alias/werant-rotation-key",
	}
	call := &encryptCall{}

	result, err := CreateSigningKey(CreateSigningKeyConstructorDep{
		RSAKeys: rsaKeysStub{keys: &ports.Keys{
			Kid:        "019a92fe-5400-7abc-8000-000000000002",
			PublicKey:  []byte("public-jwk"),
			PrivateKey: []byte("private-key"),
		}},
		KMS: kmsStub{dek: dek},
		Encrypt: encryptStub{
			encrypted: &ports.Encrypted{
				EncryptedDek:        []byte("wrapped-dek"),
				EncryptedPrivateKey: []byte("encrypted-private-key"),
				Nonce:               []byte("0123456789ab"),
				Version:             "v1",
			},
			received: call,
		},
		Id:    idStub{id: &id},
		Clock: clockStub{now: "2026-11-17T20:00:00Z"},
		Ctx:   context.Background(),
	})
	if err != nil {
		t.Fatalf("CreateSigningKey() error = %v", err)
	}

	want := entities.SigningKey{
		Id:                  id,
		Kid:                 "019a92fe-5400-7abc-8000-000000000002",
		Algorithm:           "RS256",
		Status:              "pending",
		Version:             "v1",
		PublicJwk:           []byte("public-jwk"),
		EncryptedPrivateKey: []byte("encrypted-private-key"),
		EncryptedDek:        []byte("wrapped-dek"),
		Nonce:               []byte("0123456789ab"),
		KmsKeyId:            "alias/werant-rotation-key",
		CreatedAt:           "2026-11-17T20:00:00Z",
		UpdatedAt:           "2026-11-17T20:00:00Z",
	}

	if !reflect.DeepEqual(result, want) {
		t.Errorf("CreateSigningKey() = %#v, want %#v", result, want)
	}
	if call.dek != dek {
		t.Error("GenerateEncryption() did not receive generated DEK")
	}
	if string(call.privateKey) != "private-key" {
		t.Errorf("GenerateEncryption() private key = %q", call.privateKey)
	}
	if call.kid != want.Kid {
		t.Errorf("GenerateEncryption() kid = %q, want %q", call.kid, want.Kid)
	}
}

func TestCreateSigningKeyPropagatesDependencyErrors(t *testing.T) {
	errRSA := errors.New("rsa failed")
	errKMS := errors.New("kms failed")
	errEncrypt := errors.New("encrypt failed")
	errID := errors.New("id failed")
	id := "id"

	tests := []struct {
		name string
		dep  CreateSigningKeyConstructorDep
		want error
	}{
		{
			name: "RSA generator",
			dep: CreateSigningKeyConstructorDep{
				RSAKeys: rsaKeysStub{err: errRSA},
			},
			want: errRSA,
		},
		{
			name: "KMS",
			dep: CreateSigningKeyConstructorDep{
				RSAKeys: rsaKeysStub{keys: &ports.Keys{}},
				KMS:     kmsStub{err: errKMS},
			},
			want: errKMS,
		},
		{
			name: "encryptor",
			dep: CreateSigningKeyConstructorDep{
				RSAKeys: rsaKeysStub{keys: &ports.Keys{}},
				KMS:     kmsStub{dek: &ports.DEK{}},
				Encrypt: encryptStub{err: errEncrypt},
			},
			want: errEncrypt,
		},
		{
			name: "ID generator",
			dep: CreateSigningKeyConstructorDep{
				RSAKeys: rsaKeysStub{keys: &ports.Keys{}},
				KMS:     kmsStub{dek: &ports.DEK{}},
				Encrypt: encryptStub{encrypted: &ports.Encrypted{}},
				Id:      idStub{id: &id, err: errID},
			},
			want: errID,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CreateSigningKey(test.dep)
			if !errors.Is(err, test.want) {
				t.Fatalf("CreateSigningKey() error = %v, want %v", err, test.want)
			}
		})
	}
}
