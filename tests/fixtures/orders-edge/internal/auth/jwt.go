// Package auth checks the RS256 bearer tokens issued by the identity service.
package auth

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ErrNoToken means the request carried no bearer token.
var ErrNoToken = errors.New("auth: no bearer token")

// Verifier accepts RS256 tokens signed by one identity-service key.
type Verifier struct {
	Key      *rsa.PublicKey
	Audience string
}

// Subject returns the token's subject if the request's bearer token is valid.
func (v Verifier) Subject(r *http.Request) (string, error) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || raw == "" {
		return "", ErrNoToken
	}
	tok, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return v.Key, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(v.Audience), jwt.WithExpirationRequired())
	if err != nil {
		return "", err
	}
	return tok.Claims.GetSubject()
}
