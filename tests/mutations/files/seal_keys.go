package seal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// NewKey still makes a P-256 key.
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
