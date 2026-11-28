//go:build darwin

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// macOS의 플랫폼 검증기(RootCAs가 nil이면 Go가 쓰는 SecTrustEvaluateWithError)는 서버가 빠뜨린 중간 인증서를
// 자기 캐시나 네트워크로 채우고, 로그인·관리자 키체인과 신뢰 설정도 따른다. 그러면 같은 대상이 기계마다 다르게
// 판정되고 리눅스(Go 자체 검증기)와도 어긋난다. Apple 기본 루트만 읽어 Go 검증기에 넘기면 어느 맥에서나
// 리눅스와 같은 규칙(서버가 보낸 사슬 + 루트)으로 검증하고, 인증서에 적힌 주소로는 접속하지 않는다.
// ponytail: 관리자·로그인 키체인에만 있는 사설 CA는 믿지 않는다. 그런 대상은 -ca 로 CA 파일을 준다.
const appleRoots = "/System/Library/Keychains/SystemRootCertificates.keychain"

func systemRoots() (*x509.CertPool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/bin/security", "find-certificate", "-a", "-p", appleRoots).Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", appleRoots, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(out) {
		return nil, errors.New("no certificate in " + appleRoots)
	}
	return pool, nil
}
