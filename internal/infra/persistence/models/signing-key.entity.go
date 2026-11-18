package models

import "time"

type SigningKey struct {
	Id        string `gorm:"type:uuid;primaryKey"`
	Kid       string `gorm:"uniqueIndex;not null"`
	Algorithm string `gorm:"not null"`
	Status    string `gorm:"not null"`
	Version   string `gorm:"not null"`

	PublicJwk           []byte `gorm:"type:bytea;not null"`
	EncryptedPrivateKey []byte `gorm:"type:bytea;not null"`
	EncryptedDek        []byte `gorm:"type:bytea;not null"`
	Nonce               []byte `gorm:"type:bytea;not null"`
	KmsKeyId            string `gorm:"not null"`

	CreatedAt     time.Time  `gorm:"type:timestamptz;not null"`
	UpdatedAt     time.Time  `gorm:"type:timestamptz;not null"`
	ActivatedAt   *time.Time `gorm:"type:timestamptz"`
	DeactivatedAt *time.Time `gorm:"type:timestamptz"`
	RetiredAt     *time.Time `gorm:"type:timestamptz"`
}

func (SigningKey) TableName() string {
	return "signing_keys"
}
