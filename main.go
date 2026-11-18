package main

// TIP <p>To run your code, right-click the code and select <b>Run</b>.</p> <p>Alternatively, click
// the <icon src="AllIcons.Actions.Execute"/> icon in the gutter and select the <b>Run</b> menu item from here.</p>
import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/google/uuid"
)

type JWK struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	E   string `json:"e"`
	N   string `json:"n"`
}

func main() {
	id, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}

	kid := id.String()
	key, err := rsa.GenerateKey(rand.Reader, 3072)

	if err != nil {
		panic(err)
	}

	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}

	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())

	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())

	jwk := JWK{
		Kty: "RSA",
		Alg: "RS256",
		Kid: kid,
		Use: "sig",
		E:   e,
		N:   n,
	}

	result, err := json.MarshalIndent(jwk, "", " ")

	if err != nil {
		panic(err)
	}

	fmt.Printf("%s\n", result)
	fmt.Printf("privatekey : %v\n", privateKey)
}
