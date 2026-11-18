package persistence

import (
	"context"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DbClient struct {
	Db  *gorm.DB
	Ctx context.Context
}

func NewDbClient(dsn string, ctx context.Context) (DbClient, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		return DbClient{}, err
	}

	return DbClient{
		Db:  db,
		Ctx: ctx,
	}, err
}
