package config

import (
	"strings"
	"testing"
)

func TestStartLoadsRequiredEnvironment(t *testing.T) {
	t.Setenv("POSTGRES_URL", "postgres://rotation:secret@localhost:5432/werant")
	t.Setenv("KMS_KEY_ID", "alias/werant-rotation-key")
	t.Setenv("SIGNING_KEY_VERSION", "v1")
	t.Setenv("AWS_REGION", "sa-east-1")

	environment, err := Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if environment.PostgresURL != "postgres://rotation:secret@localhost:5432/werant" {
		t.Errorf("PostgresURL = %q", environment.PostgresURL)
	}
	if environment.KMSKeyID != "alias/werant-rotation-key" {
		t.Errorf("KMSKeyID = %q", environment.KMSKeyID)
	}
	if environment.SigningKeyVersion != "v1" {
		t.Errorf("SigningKeyVersion = %q", environment.SigningKeyVersion)
	}
	if environment.AWSRegion != "sa-east-1" {
		t.Errorf("AWSRegion = %q", environment.AWSRegion)
	}
}

func TestStartReportsAllMissingEnvironmentVariables(t *testing.T) {
	for _, name := range []string{
		"POSTGRES_URL",
		"KMS_KEY_ID",
		"SIGNING_KEY_VERSION",
		"AWS_REGION",
	} {
		t.Setenv(name, "")
	}

	_, err := Start()
	if err == nil {
		t.Fatal("Start() error = nil, want missing environment variables error")
	}

	for _, name := range []string{
		"POSTGRES_URL",
		"KMS_KEY_ID",
		"SIGNING_KEY_VERSION",
		"AWS_REGION",
	} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("Start() error = %q, want variable %q", err, name)
		}
	}
}

func TestStartRejectsWhitespaceOnlyValues(t *testing.T) {
	t.Setenv("POSTGRES_URL", "postgres://rotation:secret@localhost:5432/werant")
	t.Setenv("KMS_KEY_ID", "   ")
	t.Setenv("SIGNING_KEY_VERSION", "v1")
	t.Setenv("AWS_REGION", "sa-east-1")

	_, err := Start()
	if err == nil || !strings.Contains(err.Error(), "KMS_KEY_ID") {
		t.Fatalf("Start() error = %v, want missing KMS_KEY_ID error", err)
	}
}
