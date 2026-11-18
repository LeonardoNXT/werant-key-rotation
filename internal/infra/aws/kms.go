package aws

import (
	"context"
	"cryptographic/internal/application/ports"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type KMS struct{}

func CreateKMS() KMS {
	return KMS{}
}

func (KMS) GenerateDataEncryptionKey(ctx context.Context) (*ports.DEK, error) {

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("sa-east-1"))

	if err != nil {
		return nil, fmt.Errorf("[AWS][KMS][LOAD-DEFAULT-CONFIG][ERROR] " + err.Error())
	}

	client := kms.NewFromConfig(cfg)

	keyID := os.Getenv("KMS_KEY_ID")

	keys, err := client.GenerateDataKey(
		ctx,
		&kms.GenerateDataKeyInput{
			KeyId:   &keyID,
			KeySpec: types.DataKeySpecAes256,
		},
	)

	if err != nil {
		return nil, fmt.Errorf("[AWS][KMS][GENERATE-DATA-KEY][ERROR] " + err.Error())
	}

	return &ports.DEK{
		PlainText:      keys.Plaintext,
		CipherTextBlob: keys.CiphertextBlob,
		KmsKeyId:       *keys.KeyId,
	}, nil
}
