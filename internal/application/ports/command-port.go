package ports

import "cryptographic/internal/domain/entities"

type Command interface {
	RotateSigningKeys(release *entities.SigningKey, next entities.SigningKey) error
}
