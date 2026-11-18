package usecase

import (
	"context"
	"cryptographic/internal/application/ports"
	"cryptographic/internal/application/services"
	"cryptographic/internal/domain/entities"
)

type PipelineUsecase struct {
	dep *PipelineDep
}
type PipelineDep struct {
	ports.RSAKeys
	ports.Command
	ports.Encrypt
	ports.Query
	ports.Clock
	ports.KMS
	ports.Id
	Ctx context.Context
}

func CreateUsecase(dep *PipelineDep) PipelineUsecase {
	return PipelineUsecase{
		dep,
	}
}

func (usecase PipelineUsecase) Exec() error {

	isFirstTime, err := usecase.dep.Query.IsFirstRotation()

	if err != nil {
		return err
	}

	var nextSigningKey entities.SigningKey
	var releaseSigningKey *entities.SigningKey

	if isFirstTime {
		release, err := services.CreateSigningKey(services.CreateSigningKeyConstructorDep{
			RSAKeys: usecase.dep.RSAKeys,
			Encrypt: usecase.dep.Encrypt,
			Clock:   usecase.dep.Clock,
			KMS:     usecase.dep.KMS,
			Id:      usecase.dep.Id,
			Ctx:     usecase.dep.Ctx,
		})

		if err != nil {
			return err
		}

		releaseSigningKey = &release
	}

	nextSigningKey, err = services.CreateSigningKey(services.CreateSigningKeyConstructorDep{
		RSAKeys: usecase.dep.RSAKeys,
		Encrypt: usecase.dep.Encrypt,
		Clock:   usecase.dep.Clock,
		KMS:     usecase.dep.KMS,
		Id:      usecase.dep.Id,
		Ctx:     usecase.dep.Ctx,
	})

	if err != nil {
		return err
	}

	err = usecase.dep.Command.RotateSigningKeys(releaseSigningKey, nextSigningKey)

	if err != nil {
		return err
	}

	return nil
}
