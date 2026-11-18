package ports

type Keys struct {
	Kid        string
	PublicKey  []byte
	PrivateKey []byte
}

type RSAKeys interface {
	GenerateRSAKeys() (*Keys, error)
}
