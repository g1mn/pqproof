package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"

	"golang.org/x/crypto/ssh"
)

func main() {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = md5.Sum([]byte("x"))
	dk, _ := mlkem.GenerateKey768()
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS10,
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
	}
	_, _, _, _, _ = rk, ek, dk, cfg, ssh.KeyAlgoRSA
}
