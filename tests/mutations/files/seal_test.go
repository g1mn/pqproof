package seal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// Negative test: an old P-256 key must be rejected.
func TestRejectsP256(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if accept(k) {
		t.Fatal("P-256 key must be rejected")
	}
}
