package aws

import (
	"context"
	"cryptographic/internal/application/ports"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type KMS struct {
	region string
	keyID  string
}

func CreateKMS(region string, keyID string) KMS {
	return KMS{
		region: region,
		keyID:  keyID,
	}
}

func (adapter KMS) GenerateDataEncryptionKey(ctx context.Context) (*ports.DEK, error) {

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(adapter.region))

	if err != nil {
		return nil, fmt.Errorf("[AWS][KMS][LOAD-DEFAULT-CONFIG][ERROR] %w", err)
	}

	client := kms.NewFromConfig(cfg)

	keys, err := client.GenerateDataKey(
		ctx,
		&kms.GenerateDataKeyInput{
			KeyId:   &adapter.keyID,
			KeySpec: types.DataKeySpecAes256,
		},
	)

	if err != nil {
		return nil, fmt.Errorf("[AWS][KMS][GENERATE-DATA-KEY][ERROR] %w", err)
	}

	return &ports.DEK{
		PlainText:      keys.Plaintext,
		CipherTextBlob: keys.CiphertextBlob,
		KmsKeyId:       *keys.KeyId,
	}, nil
}
