package command

import (
	"context"
	"cryptographic/internal/domain/entities"
	"cryptographic/internal/infra/persistence/mappers"
	"cryptographic/internal/infra/persistence/models"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type Command struct {
	db  *gorm.DB
	ctx context.Context
}

func CreateCommand(db *gorm.DB, ctx context.Context) (*Command, error) {

	if db == nil {
		return nil, fmt.Errorf("[ERROR][DB][SIGNING_KEY][COMMAND] database is empty")
	}

	return &Command{db, ctx}, nil
}

func (cmd *Command) RotateSigningKeys(release *entities.SigningKey, next entities.SigningKey) error {
	var releaseModel *models.SigningKey
	var isFirstRotation bool

	if release != nil {
		var err error
		releaseModel, err = mappers.SigningKeyToORM(*release)
		isFirstRotation = true
		if err != nil {
			return err
		}
	}

	nextModel, err := mappers.SigningKeyToORM(next)
	if err != nil {
		return err
	}

	return cmd.db.Transaction(func(tx *gorm.DB) error {
		now := time.Now()

		if releaseModel != nil {
			err = gorm.G[models.SigningKey](tx).Create(cmd.ctx, releaseModel)
			if err != nil {
				return err
			}
		}

		// rotation retired signing_keys
		resRetired := tx.WithContext(cmd.ctx).Exec(`

          UPDATE signing_keys
          SET status = 'retired', retired_at = ?, updated_at = NOW()
          WHERE status = 'deactivated'
             AND activated_at IS NOT NULL
             AND deactivated_at IS NOT NULL
             AND retired_at IS NULL
          
       `, now)

		if resRetired.Error != nil {
			return resRetired.Error
		}

		// rotation deactivated signing_keys
		resDeactivated := tx.WithContext(cmd.ctx).Exec(`

          UPDATE signing_keys
          SET status = 'deactivated', deactivated_at = ?, updated_at = NOW()
          WHERE status = 'active'
             AND activated_at IS NOT NULL
             AND deactivated_at IS NULL
             AND retired_at IS NULL
          
       `, now)
		if resDeactivated.Error != nil {
			return resDeactivated.Error
		}

		// rotation active signing_keys

		resActive := tx.WithContext(cmd.ctx).Exec(`

          UPDATE signing_keys
          SET status = 'active', activated_at = ?, updated_at = NOW()
          WHERE status = 'pending'
             AND activated_at IS NULL
             AND deactivated_at IS NULL
             AND retired_at IS NULL
          
       `, now)
		if resActive.Error != nil {
			return resActive.Error
		}

		// creating next signing key

		if err = gorm.G[models.SigningKey](tx).Create(cmd.ctx, nextModel); err != nil {
			return err
		}

		if isFirstRotation {
			fmt.Printf("[DB][SIGNING_KEY] FIRST SIGNING KEY CREATED \n")
		}

		fmt.Printf("[DB][SIGNING_KEY][COMMAND] UPDATED status 'active' count: %d\n", resActive.RowsAffected)
		fmt.Printf("[DB][SIGNING_KEY][COMMAND] UPDATED status 'deactivated' count: %d\n", resDeactivated.RowsAffected)
		fmt.Printf("[DB][SIGNING_KEY][COMMAND] UPDATED status 'retired' count: %d\n", resRetired.RowsAffected)
		fmt.Printf("[DB][SIGNING_KEY][COMMAND] NEXT SIGNING KEY CREATED \n")

		return nil
	})
}
