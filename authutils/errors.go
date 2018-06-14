package authutils

import (
	"errors"
	"fmt"
	"strings"
)

func validationError(reason string) error {
	msg := fmt.Sprintf("cannot validate token; %s", reason)
	return errors.New(msg)
}

func fieldTypeError(field string, expectedType string) error {
	msg := fmt.Sprintf("received value for field `%s` with incorrect type; expected %s\n", field, expectedType)
	return errors.New(msg)
}

func missingField(field string) error {
	msg := fmt.Sprintf("token missing required field: %s\n", field)
	return errors.New(msg)
}

func invalidIssuer(received string) error {
	msg := fmt.Sprintf("invalid issuer: %s\n", received)
	return errors.New(msg)
}

func invalidPurpose(received string, expected string) error {
	msg := fmt.Sprintf("invalid purpose: %s; expected: %s\n", received, expected)
	return errors.New(msg)
}

func expired(timestamp int64) error {
	msg := fmt.Sprintf("expired at time: %d\n", timestamp)
	return errors.New(msg)
}

func missingAudience(missingAud string, containsAuds []string) error {
	containsString := strings.Join(containsAuds, ", ")
	msg := fmt.Sprintf("token missing required audience: %s; contains: %s\n", missingAud, containsString)
	return errors.New(msg)
}
