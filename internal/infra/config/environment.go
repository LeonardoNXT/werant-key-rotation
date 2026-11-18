package config

import (
	"errors"
	"os"
)

type Environment struct {
	PostgresURL string
}

func Start() (*Environment, error) {
	postgresURL := os.Getenv("POSTGRES_URL")

	if postgresURL == "" {
		return nil, errors.New("POSTGRES_URL environment variable not set")
	}

	return &Environment{
		PostgresURL: postgresURL,
	}, nil
}
