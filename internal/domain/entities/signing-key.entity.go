package entities

type SigningKey struct {
	Id        string
	Kid       string
	Algorithm string
	Status    string
	Version   string

	PublicJwk           []byte
	EncryptedPrivateKey []byte
	EncryptedDek        []byte
	Nonce               []byte
	KmsKeyId            string

	CreatedAt     string
	UpdatedAt     string
	ActivatedAt   *string
	DeactivatedAt *string
	RetiredAt     *string
}
