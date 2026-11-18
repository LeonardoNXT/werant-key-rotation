package config

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

type Environment struct {
	PostgresURL       string
	KMSKeyID          string
	SigningKeyVersion string
	AWSRegion         string
}

func Start() (*Environment, error) {
	values := map[string]string{
		"POSTGRES_URL":        strings.TrimSpace(os.Getenv("POSTGRES_URL")),
		"KMS_KEY_ID":          strings.TrimSpace(os.Getenv("KMS_KEY_ID")),
		"SIGNING_KEY_VERSION": strings.TrimSpace(os.Getenv("SIGNING_KEY_VERSION")),
		"AWS_REGION":          strings.TrimSpace(os.Getenv("AWS_REGION")),
	}

	missing := make([]string, 0, len(values))
	for name, value := range values {
		if value == "" {
			missing = append(missing, name)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("required environment variables not set: %s", strings.Join(missing, ", "))
	}

	return &Environment{
		PostgresURL:       values["POSTGRES_URL"],
		KMSKeyID:          values["KMS_KEY_ID"],
		SigningKeyVersion: values["SIGNING_KEY_VERSION"],
		AWSRegion:         values["AWS_REGION"],
	}, nil
}
