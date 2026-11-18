package main

import (
	"cryptographic/internal/infra/bootstrap"

	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	lambda.Start(bootstrap.Start)
}
