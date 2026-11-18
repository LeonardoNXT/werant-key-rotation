package bootstrap

import (
	"context"
	"cryptographic/internal/application/usecase"
	"cryptographic/internal/infra/adapters"
	"cryptographic/internal/infra/aws"
	"cryptographic/internal/infra/config"
	"cryptographic/internal/infra/persistence"
	"cryptographic/internal/infra/persistence/command"
	"cryptographic/internal/infra/persistence/query"
)

func Start(ctx context.Context) {
	environment, err := config.Start()

	if err != nil {
		panic(err)
	}

	client, err := persistence.NewDbClient(environment.PostgresURL, ctx)

	if err != nil {
		panic(err)
	}

	commandDep, err := command.CreateCommand(client.Db, client.Ctx)

	if err != nil {
		panic(err)
	}

	queryDep, err := query.CreateQuery(client.Db, client.Ctx)

	if err != nil {
		panic(err)
	}

	dep := &usecase.PipelineDep{
		RSAKeys: adapters.RSAKeys{},
		Command: commandDep,
		Encrypt: adapters.Encrypt{},
		Query:   queryDep,
		Clock:   adapters.Clock{},
		KMS:     aws.CreateKMS(),
		Id:      adapters.IdGenerator{},
		Ctx:     ctx,
	}

	pipelineUsecase := usecase.CreateUsecase(dep)

	if err := pipelineUsecase.Exec(); err != nil {
		panic(err)
	}

}
