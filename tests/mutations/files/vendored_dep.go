// Vendored third-party module (top-level vendor/ is skipped as a dependency folder).
package legacy

import (
	"crypto/rand"
	"crypto/rsa"
)

func NewKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }
