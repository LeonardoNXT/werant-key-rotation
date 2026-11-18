package ports

type Encrypted struct {
	EncryptedDek        []byte
	EncryptedPrivateKey []byte
	Nonce               []byte
	Version             string
}

type Encrypt interface {
	GenerateEncryption(dek *DEK, privateKey []byte, kid string) (*Encrypted, error)
}
