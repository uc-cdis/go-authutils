package authutils

import (
	"fmt"
	"testing"
)

var REQUIRED_CLAIMS []string = []string{
	"aud",
	"exp",
	"iss",
}

/*
 * Look in `test_utils.go` for the utility functions that are used in this file.
 */

// TestMissingExpiration verifies that if a token is missing the `exp` field
// that it will not validate.
func TestMissingExpiration(t *testing.T) {
}

func TestDecodeToken(t *testing.T) {
	application, _, encodedToken, _ := makeDefaultApplicationAndToken()
	claims, err := application.Decode(encodedToken)
	if err != nil {
		t.Fatalf("failed to decode valid token: %s", err)
	}

	for _, field := range REQUIRED_CLAIMS {
		_, exists := (*claims)[field]
		if !exists {
			t.Fatalf("token missing required claim: %s", field)
		}
	}
}

func TestValidateRequest(t *testing.T) {
	// TODO
}

// benchmarkDecodeTokenOfLength takes a number of bytes as an argument and
// benchmarks decoding a token which is approximately that many bytes long.
func benchmarkDecodeTokenOfLength(bytes int) func(*testing.B) {
	runBenchmark := func(b *testing.B) {
		b.StopTimer()
		keyID := "keyID"
		encodedToken, publicKey := generateTokenOfLength(bytes, keyID)
		application := makeApplicationWithKey(keyID, publicKey)
		b.StartTimer()
		for i := 0; i < b.N; i++ {
			application.Decode(encodedToken)
		}
		b.StopTimer()
	}
	return runBenchmark
}

func TestMissing(t *testing.T) {
	application, defaultClaims, _, builder := makeDefaultApplicationAndToken()
	expected := makeDefaultExpected()

	t.Run("exp", func(t *testing.T) {
		// Setup claims with missing field.
		claims := make(Claims)
		for k, v := range *defaultClaims {
			claims[k] = v
		}
		delete(claims, "exp")
		encodedTokenMissingExpiration, err := builder.Claims(claims).CompactSerialize()
		if err != nil {
			panic(err)
		}

		// Try to decode and then validate the claims and make sure there is an
		// error.
		decodedClaims, err := application.Decode(encodedTokenMissingExpiration)
		if err != nil {
			panic(err)
		}
		err = expected.Validate(decodedClaims)
		if err == nil {
			t.Fatal("token missing `exp` field validated successfully")
		}
	})

	t.Run("iss", func(t *testing.T) {
		// Setup claims with missing field.
		claims := make(Claims)
		for k, v := range *defaultClaims {
			claims[k] = v
		}
		delete(claims, "iss")
		encodedTokenMissingIssuer, err := builder.Claims(claims).CompactSerialize()
		if err != nil {
			panic(err)
		}

		// Try to decode and then validate the claims and make sure there is an
		// error.
		decodedClaims, err := application.Decode(encodedTokenMissingIssuer)
		if err != nil {
			panic(err)
		}
		err = expected.Validate(decodedClaims)
		if err == nil {
			t.Fatal("token missing `iss` field validated successfully")
		}
	})
}

// BenchmarkDecodeToken runs a table of benchmarks for decoding tokens with
// various lengths.
func BenchmarkDecodeToken(b *testing.B) {
	for i := uint(9); i < 16; i++ {
		n := 1 << i
		name := fmt.Sprintf("bytes=%d (2^%d)", n, i)
		b.Run(name, benchmarkDecodeTokenOfLength(n))
	}
}
