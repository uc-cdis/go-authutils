package authutils

import (
	"testing"
)

func TestContains(t *testing.T) {
	t.Run("true", func(t *testing.T) {
		result := contains("a", []string{"x", "y", "z", "a", "b", "c"})
		if !result {
			t.Fail()
		}
	})

	t.Run("false", func(t *testing.T) {
		result := contains("a", []string{"x", "y", "z", "abc"})
		if result {
			t.Fail()
		}
	})
}
