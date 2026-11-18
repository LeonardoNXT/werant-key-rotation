package ports

import "context"

type DEK struct {
	PlainText      []byte
	CipherTextBlob []byte
	KmsKeyId       string
}

type KMS interface {
	GenerateDataEncryptionKey(ctx context.Context) (*DEK, error)
}
