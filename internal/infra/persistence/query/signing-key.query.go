package query

import (
	"context"
	"cryptographic/internal/infra/persistence/models"
	"fmt"

	"gorm.io/gorm"
)

type Query struct {
	db  *gorm.DB
	ctx context.Context
}

func CreateQuery(db *gorm.DB, ctx context.Context) (*Query, error) {
	if db == nil {
		return nil, fmt.Errorf("[ERROR][DB][SIGNING_KEY][QUERY] database is empty")
	}

	return &Query{
		db,
		ctx,
	}, nil
}

func (query Query) IsFirstRotation() (bool, error) {
	var count int64

	err := query.db.WithContext(query.ctx).
		Model(&models.SigningKey{}).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	return count == 0, nil
}
