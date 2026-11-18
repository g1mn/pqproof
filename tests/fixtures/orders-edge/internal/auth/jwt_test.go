package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func sign(t *testing.T, key *rsa.PrivateKey, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSubject(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	v := Verifier{Key: &key.PublicKey, Audience: "orders"}
	good := jwt.MapClaims{"sub": "user-7", "aud": "orders", "exp": time.Now().Add(time.Minute).Unix()}
	cases := []struct {
		name, header, want string
		ok                 bool
	}{
		{"valid", "Bearer " + sign(t, key, jwt.SigningMethodRS256, good), "user-7", true},
		{"missing", "", "", false},
		{"wrong audience", "Bearer " + sign(t, key, jwt.SigningMethodRS256,
			jwt.MapClaims{"sub": "u", "aud": "billing", "exp": time.Now().Add(time.Minute).Unix()}), "", false},
		{"expired", "Bearer " + sign(t, key, jwt.SigningMethodRS256,
			jwt.MapClaims{"sub": "u", "aud": "orders", "exp": time.Now().Add(-time.Minute).Unix()}), "", false},
		{"PS256 refused", "Bearer " + sign(t, key, jwt.SigningMethodPS256, good), "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/orders/1", nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			got, err := v.Subject(r)
			if (err == nil) != c.ok || got != c.want {
				t.Fatalf("Subject() = %q, %v; want %q, ok=%v", got, err, c.want, c.ok)
			}
		})
	}
}
