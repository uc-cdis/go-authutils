package authutils

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// makeApplicationWithKey returns a JWTApplication initialized with the given
// publicKey which can be used to validate JWTs.
func makeApplicationWithKey(keyID string, publicKey *rsa.PublicKey) *JWTApplication {
	application := NewJWTApplication("https://example-iss.net/.well-known/jwks")
	jwk := publicKeyToJWK(keyID, publicKey)
	application.Keys.Insert(jwk)
	return application
}

// generateKeypair randomly creates a new RSA public and private keypair.
func generateKeypair(keyID string) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1<<10)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.Public().(*rsa.PublicKey)
	return privateKey, publicKey
}

func makeDefaultApplicationAndToken() (*JWTApplication, *Claims, EncodedToken, jwt.Builder) {
	keyID := "default"
	privateKey, publicKey := generateKeypair(keyID)

	application := makeApplicationWithKey("default", publicKey)

	key := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       privateKey,
	}
	options := jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": keyID,
		},
	}
	signer, err := jose.NewSigner(key, &options)
	if err != nil {
		panic(err)
	}

	claims := makeDefaultClaims()
	encodedToken, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	builder := jwt.Signed(signer)

	return application, &claims, encodedToken, builder
}

// publicKeyToJWK basically just does a type conversion from an `rsa.PublicKey`
// to a `jose.JSONWebKey`.
func publicKeyToJWK(keyID string, publicKey *rsa.PublicKey) jose.JSONWebKey {
	jwk := jose.JSONWebKey{
		Key:       publicKey,
		KeyID:     keyID,
		Algorithm: "RS256",
	}
	return jwk
}

// makeDefaultClaims returns some basic example claims to put in a token.
func makeDefaultClaims() Claims {
	exampleClaims := Claims{
		"aud": []string{"test"},
		"iss": "https://example-iss.net",
		"exp": time.Now().Unix() + 1000,
		"pur": "access",
	}

	return exampleClaims
}

func makeDefaultExpected() Expected {
	purpose := "access"
	expected := Expected{
		Audiences:  []string{"test"},
		Issuers:    []string{"https://example-iss.net"},
		Expiration: time.Now().Unix(),
		Purpose:    &purpose,
	}
	return expected
}

// generateTokenOfLength generates a valid encoded JWT with the specified
// length in bytes.
func generateTokenOfLength(bytes int, keyID string) (string, *rsa.PublicKey) {
	privateKey, publicKey := generateKeypair(keyID)
	key := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       privateKey,
	}
	options := jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": keyID,
		},
	}
	signer, err := jose.NewSigner(key, &options)
	if err != nil {
		panic(err)
	}

	claims := makeDefaultClaims()
	currentResult, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}
	// Dump extra stuff in the token so that it ends up with the desired
	// length.
	currentLength := len(currentResult)
	needBytes := bytes - currentLength
	// This is the minimum amount of filler that needs to be added (an
	// additional field in the token which will hold the filler bytes).
	addingText := "filler:\"\",\n"
	if needBytes < len(addingText) {
		msg := fmt.Sprintf("can't generate token with this few bytes: %d\n", bytes)
		panic(errors.New(msg))
	}
	// Convert from the number of additional bytes needed to how many
	// characters we should add to the un-encoded token.
	needDecodedLength := (needBytes / 4) * 3
	needDecodedLength -= len("filler:\"\",\n")
	// Put in the filler.
	claims["filler"] = strings.Repeat("*", needDecodedLength)

	result, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	if err != nil {
		panic(err)
	}

	return result, publicKey
}
