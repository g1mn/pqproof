//go:build !darwin

package main

import "crypto/x509"

// 리눅스에서는 RootCAs가 nil이면 Go가 디스크의 루트(/etc/ssl 등)를 읽어 자기 검증기로 검증한다. 네트워크 조회도 없다.
func systemRoots() (*x509.CertPool, error) { return nil, nil }
