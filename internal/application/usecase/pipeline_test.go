package usecase

import (
	"context"
	"errors"
	"testing"

	"cryptographic/internal/application/ports"
	"cryptographic/internal/domain/entities"
)

type queryStub struct {
	first bool
	err   error
}

func (stub queryStub) IsFirstRotation() (bool, error) {
	return stub.first, stub.err
}

type rsaSequenceStub struct {
	kids  []string
	err   error
	calls int
}

func (stub *rsaSequenceStub) GenerateRSAKeys() (*ports.Keys, error) {
	if stub.err != nil {
		return nil, stub.err
	}
	if stub.calls >= len(stub.kids) {
		return nil, errors.New("unexpected RSA generation call")
	}

	kid := stub.kids[stub.calls]
	stub.calls++
	return &ports.Keys{
		Kid:        kid,
		PublicKey:  []byte("public-" + kid),
		PrivateKey: []byte("private-" + kid),
	}, nil
}

type kmsSequenceStub struct{}

func (kmsSequenceStub) GenerateDataEncryptionKey(context.Context) (*ports.DEK, error) {
	return &ports.DEK{
		PlainText:      []byte("01234567890123456789012345678901"),
		CipherTextBlob: []byte("wrapped-dek"),
		KmsKeyId:       "kms-key",
	}, nil
}

type encryptSequenceStub struct{}

func (encryptSequenceStub) GenerateEncryption(_ *ports.DEK, privateKey []byte, _ string) (*ports.Encrypted, error) {
	return &ports.Encrypted{
		EncryptedDek:        []byte("wrapped-dek"),
		EncryptedPrivateKey: append([]byte("encrypted-"), privateKey...),
		Nonce:               []byte("0123456789ab"),
		Version:             "v1",
	}, nil
}

type clockSequenceStub struct{}

func (clockSequenceStub) NowISO8601() string {
	return "2026-11-17T20:00:00Z"
}

type idSequenceStub struct {
	ids   []string
	calls int
}

func (stub *idSequenceStub) IdGenerator() (*string, error) {
	if stub.calls >= len(stub.ids) {
		return nil, errors.New("unexpected ID generation call")
	}
	id := stub.ids[stub.calls]
	stub.calls++
	return &id, nil
}

type commandSpy struct {
	release *entities.SigningKey
	next    entities.SigningKey
	err     error
	calls   int
}

func (spy *commandSpy) RotateSigningKeys(release *entities.SigningKey, next entities.SigningKey) error {
	spy.release = release
	spy.next = next
	spy.calls++
	return spy.err
}

func TestPipelineExecFirstRotationCreatesReleaseAndNextKeys(t *testing.T) {
	rsa := &rsaSequenceStub{kids: []string{"release-kid", "next-kid"}}
	ids := &idSequenceStub{ids: []string{"release-id", "next-id"}}
	command := &commandSpy{}

	usecase := CreateUsecase(&PipelineDep{
		Query:   queryStub{first: true},
		RSAKeys: rsa,
		KMS:     kmsSequenceStub{},
		Encrypt: encryptSequenceStub{},
		Clock:   clockSequenceStub{},
		Id:      ids,
		Command: command,
		Ctx:     context.Background(),
	})

	if err := usecase.Exec(); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}

	if command.calls != 1 {
		t.Fatalf("RotateSigningKeys() calls = %d, want 1", command.calls)
	}
	if command.release == nil {
		t.Fatal("release key = nil, want first-rotation release key")
	}
	if command.release.Id != "release-id" || command.release.Kid != "release-kid" {
		t.Errorf("release key = %#v", *command.release)
	}
	if command.next.Id != "next-id" || command.next.Kid != "next-kid" {
		t.Errorf("next key = %#v", command.next)
	}
	if rsa.calls != 2 {
		t.Errorf("GenerateRSAKeys() calls = %d, want 2", rsa.calls)
	}
}

func TestPipelineExecRegularRotationCreatesOnlyNextKey(t *testing.T) {
	rsa := &rsaSequenceStub{kids: []string{"next-kid"}}
	ids := &idSequenceStub{ids: []string{"next-id"}}
	command := &commandSpy{}

	usecase := CreateUsecase(&PipelineDep{
		Query:   queryStub{first: false},
		RSAKeys: rsa,
		KMS:     kmsSequenceStub{},
		Encrypt: encryptSequenceStub{},
		Clock:   clockSequenceStub{},
		Id:      ids,
		Command: command,
		Ctx:     context.Background(),
	})

	if err := usecase.Exec(); err != nil {
		t.Fatalf("Exec() error = %v", err)
	}

	if command.release != nil {
		t.Errorf("release key = %#v, want nil", command.release)
	}
	if command.next.Id != "next-id" || command.next.Kid != "next-kid" {
		t.Errorf("next key = %#v", command.next)
	}
	if rsa.calls != 1 {
		t.Errorf("GenerateRSAKeys() calls = %d, want 1", rsa.calls)
	}
}

func TestPipelineExecPropagatesQueryError(t *testing.T) {
	wantErr := errors.New("query failed")
	usecase := CreateUsecase(&PipelineDep{
		Query: queryStub{err: wantErr},
	})

	if err := usecase.Exec(); !errors.Is(err, wantErr) {
		t.Fatalf("Exec() error = %v, want %v", err, wantErr)
	}
}

func TestPipelineExecPropagatesKeyCreationError(t *testing.T) {
	wantErr := errors.New("RSA failed")
	command := &commandSpy{}
	usecase := CreateUsecase(&PipelineDep{
		Query:   queryStub{first: false},
		RSAKeys: &rsaSequenceStub{err: wantErr},
		Command: command,
	})

	if err := usecase.Exec(); !errors.Is(err, wantErr) {
		t.Fatalf("Exec() error = %v, want %v", err, wantErr)
	}
	if command.calls != 0 {
		t.Errorf("RotateSigningKeys() calls = %d, want 0", command.calls)
	}
}

func TestPipelineExecPropagatesCommandError(t *testing.T) {
	wantErr := errors.New("command failed")
	usecase := CreateUsecase(&PipelineDep{
		Query:   queryStub{first: false},
		RSAKeys: &rsaSequenceStub{kids: []string{"next-kid"}},
		KMS:     kmsSequenceStub{},
		Encrypt: encryptSequenceStub{},
		Clock:   clockSequenceStub{},
		Id:      &idSequenceStub{ids: []string{"next-id"}},
		Command: &commandSpy{err: wantErr},
		Ctx:     context.Background(),
	})

	if err := usecase.Exec(); !errors.Is(err, wantErr) {
		t.Fatalf("Exec() error = %v, want %v", err, wantErr)
	}
}
