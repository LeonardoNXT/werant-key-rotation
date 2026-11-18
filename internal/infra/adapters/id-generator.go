package adapters

import (
	"fmt"

	"github.com/google/uuid"
)

type IdGenerator struct{}

func (IdGenerator) IdGenerator() (*string, error) {
	id, err := uuid.NewV7()

	if err != nil {
		return nil, fmt.Errorf("[ADAPTER][ID-GENERATOR][ERROR] generate UUIDv7: %w", err)
	}

	stringed := id.String()
	pointer := &stringed

	return pointer, nil
}
