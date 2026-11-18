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

const rotationAdvisoryLockID int64 = 8243126501933386834

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
		var lockAcquired bool

		if err := tx.WithContext(cmd.ctx).Raw(
			"SELECT pg_try_advisory_xact_lock(?)",
			rotationAdvisoryLockID,
		).Scan(&lockAcquired).Error; err != nil {
			return err
		}

		if !lockAcquired {
			fmt.Printf("[DB][SIGNING_KEY][COMMAND] ROTATION SKIPPED: another rotation is in progress\n")
			return nil
		}

		if releaseModel != nil {
			var existingKeys int64
			if err := tx.WithContext(cmd.ctx).Model(&models.SigningKey{}).Count(&existingKeys).Error; err != nil {
				return err
			}

			if existingKeys > 0 {
				fmt.Printf("[DB][SIGNING_KEY][COMMAND] FIRST ROTATION SKIPPED: signing keys already exist\n")
				return nil
			}

			err = gorm.G[models.SigningKey](tx).Create(cmd.ctx, releaseModel)
			if err != nil {
				return err
			}
		}

		// rotation retired signing_keys
		resRetired := tx.WithContext(cmd.ctx).Exec(`
          WITH candidate AS (
              SELECT id
              FROM signing_keys
              WHERE status = 'deactivated'
                AND activated_at IS NOT NULL
                AND deactivated_at IS NOT NULL
                AND retired_at IS NULL
              ORDER BY deactivated_at, id
              LIMIT 1
              FOR UPDATE
          )
          UPDATE signing_keys AS signing_key
          SET status = 'retired', retired_at = ?, updated_at = NOW()
          FROM candidate
          WHERE signing_key.id = candidate.id
       `, now)

		if resRetired.Error != nil {
			return resRetired.Error
		}

		// rotation deactivated signing_keys
		resDeactivated := tx.WithContext(cmd.ctx).Exec(`
          WITH candidate AS (
              SELECT id
              FROM signing_keys
              WHERE status = 'active'
                AND activated_at IS NOT NULL
                AND deactivated_at IS NULL
                AND retired_at IS NULL
              ORDER BY activated_at, id
              LIMIT 1
              FOR UPDATE
          )
          UPDATE signing_keys AS signing_key
          SET status = 'deactivated', deactivated_at = ?, updated_at = NOW()
          FROM candidate
          WHERE signing_key.id = candidate.id
       `, now)
		if resDeactivated.Error != nil {
			return resDeactivated.Error
		}

		// rotation active signing_keys

		resActive := tx.WithContext(cmd.ctx).Exec(`
          WITH candidate AS (
              SELECT id
              FROM signing_keys
              WHERE status = 'pending'
                AND activated_at IS NULL
                AND deactivated_at IS NULL
                AND retired_at IS NULL
              ORDER BY created_at, id
              LIMIT 1
              FOR UPDATE
          )
          UPDATE signing_keys AS signing_key
          SET status = 'active', activated_at = ?, updated_at = NOW()
          FROM candidate
          WHERE signing_key.id = candidate.id
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
