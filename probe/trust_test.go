package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// On macOS the probe must not hand verification to the platform verifier (Go uses it when RootCAs is nil): that one
// completes a chain the server left incomplete from its own cache and follows the login and admin keychains, so the
// same target would pass on one Mac, fail on another and fail on Linux.
func TestSystemRootsUseGoVerifier(t *testing.T) {
	roots, err := trustRoots("")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" && (roots == nil || len(roots.Subjects()) < 50) { //nolint:staticcheck // Subjects only counts here
		t.Fatalf("macOS roots = %v, want Apple's system roots as an explicit pool", roots)
	}
	if runtime.GOOS != "darwin" && roots != nil {
		t.Fatal("off macOS RootCAs stays nil: Go reads the roots on disk")
	}
}

// A server certificate names fetch URLs (AIA caIssuers, OCSP, CRL) on a local listener; verifying it against the
// system roots must make no request to them. On the Macs we tried the old platform verifier made none either, so
// this guards the property for whatever verifier is in use; it does not tell the old macOS path from the new one
// (TestSystemRootsUseGoVerifier does).
func TestSystemTrustFetchesNothing(t *testing.T) {
	var hits atomic.Int32
	web, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer web.Close()
	go http.Serve(web, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	url := "http://" + web.Addr().String()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "untrusted test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
		IssuingCertificateURL: []string{url + "/ca.crt"}, OCSPServer: []string{url + "/ocsp"},
		CRLDistributionPoints: []string{url + "/ca.crl"}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()

	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	code := connect([]string{"-groups=X25519", "-servername=localhost", "-wait=2s", srv.Addr().String()})
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	if code != 1 || !strings.Contains(string(out), "error: "+verifyFailed) {
		t.Fatalf("connect = %d with %q, want 1 and a verification failure (the CA is not trusted)", code, out)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("verifying against the system trust store made %d request(s) to URLs named in the server certificate", n)
	}
}
