// Command api serves the orders API over TLS. nginx (nginx/nginx.conf) sits in front of it.
package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/g1mn/orders-edge/internal/auth"
	"github.com/g1mn/orders-edge/internal/orders"
	"github.com/g1mn/orders-edge/internal/tlsconf"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9443", "listen address")
	cert := flag.String("cert", "/etc/orders-edge/tls/cert.pem", "TLS certificate (PEM)")
	key := flag.String("key", "/etc/orders-edge/tls/key.pem", "TLS private key (PEM)")
	jwtKey := flag.String("jwt-public-key", "", "identity service RSA public key (PEM) for RS256 tokens; empty serves without auth (dev only)")
	flag.Parse()

	var authn orders.Authenticator
	if *jwtKey != "" {
		pub, err := loadRSAPublicKey(*jwtKey)
		if err != nil {
			log.Fatal(err)
		}
		authn = auth.Verifier{Key: pub, Audience: "orders"}
	}
	store := orders.NewStore(orders.Order{ID: 1, Item: "keyboard", Status: "shipped"})
	srv := &http.Server{
		Addr:              *addr,
		Handler:           orders.NewHandler(store, authn),
		TLSConfig:         tlsconf.Server(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("orders api on https://%s", *addr)
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, os.ErrInvalid
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, os.ErrInvalid
	}
	return rsaPub, nil
}
