// Package tlsconf holds the TLS settings for the orders API listener.
package tlsconf

import "crypto/tls"

// Server returns the TLS configuration for the API listener.
//
// Key exchange is pinned to P-256 (decision from the 2023 compliance review).
func Server() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}
}
