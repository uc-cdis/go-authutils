package authutils

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

// REQUIRED_CLAIMS lists the claims which absolutely must appear in a token,
// whose absence will cause it not to validate.
var REQUIRED_CLAIMS []string = []string{
	"exp",
	"iss",
}

/*
 * Look in `test_utils.go` for the utility functions that are used in this file.
 */

func TestDecodeToken(t *testing.T) {
	application, _, encodedToken, _ := defaultSetup()
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

// TestValidateRequest tests creating an HTTP request with some valid claims
// and then attempting to validate them using the default application setup.
func TestValidateRequest(t *testing.T) {
	application, correctClaims, _, builder := defaultSetup()
	expected := makeDefaultExpected()
	header := makeAuthHeader(*correctClaims, builder)
	exampleURL, err := url.Parse("https://example-service.net/endpoint")
	if err != nil {
		t.Fatalf("%s", err)
	}
	request := http.Request{
		Method: "GET",
		URL:    exampleURL,
		Header: header,
	}
	_, err = application.ValidateRequest(&request, &expected)
	if err != nil {
		t.Fatalf("%s", err)
	}
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

// TestMissingRequiredClaim runs a table of subtests which check that if a
// particular required claim (in `REQUIRED_CLAIMS`) is missing from the token,
// then the validation raises an error.
func TestMissingRequiredClaim(t *testing.T) {
	application, defaultClaims, _, builder := defaultSetup()
	expected := makeDefaultExpected()

	testMissingClaim := func(claim string) func(t *testing.T) {
		return func(t *testing.T) {
			// Setup claims with missing field.
			claims := make(Claims)
			for k, v := range *defaultClaims {
				claims[k] = v
			}
			delete(claims, claim)
			encodedTokenMissingExpiration, err := builder.Claims(claims).CompactSerialize()
			if err != nil {
				panic(err)
			}

			// Try to decode and then validate the claims and make sure there
			// is an error.
			decodedClaims, err := application.Decode(encodedTokenMissingExpiration)
			if err != nil {
				panic(err)
			}
			err = expected.Validate(decodedClaims)
			if err == nil {
				t.Fatal("token missing `exp` field validated successfully")
			}
		}
	}

	// Run the test on all the required claims.
	for _, requiredClaim := range REQUIRED_CLAIMS {
		t.Run(requiredClaim, testMissingClaim(requiredClaim))
	}
}

func TestPurpose(t *testing.T) {
	// Test the case where the purpose exists and is one of the allowed values
	// but not the one expected in the token.
	t.Run("incorrect", func(t *testing.T) {
		_, claims, _, _ := defaultSetup()
		expected := makeDefaultExpected()
		// Default purpose is "access".
		wrongPurpose := "session"
		expected.Purpose = &wrongPurpose
		err := expected.Validate(claims)
		if err == nil {
			t.Fail()
		}
	})

	// Test the case that the purpose is not even one of the allowed values in
	// `ALLOWED_PURPOSES`.
	t.Run("invalid", func(t *testing.T) {
	})

	t.Run("missing", func(t *testing.T) {
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
