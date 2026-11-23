// from g1mn/pq-proof 7b7803f (MIT)
// 수정: connect는 기본으로 시스템 신뢰 저장소로 검증하고 -ca·-tofu(첫 인증서를 믿고 다시 검증)를 고를 수 있다,
//       cert_sig·cert_key·cert_chain·trust 줄, cert에 -alg=mldsa65, cipher·cert_not_after 줄, 머리 주석 한국어.
//
// tls_probe: 버전을 고정한 TLS 클라이언트(와 참조 서버). Go 표준 라이브러리만 쓰고 CGO 없이 정적으로 빌드한다
// (build-probe.sh). 같은 바이너리를 맥·리눅스 컨테이너 어디서나 쓰므로, 실패가 나오면 옛 클라이언트가
// 그룹 이름을 몰라서가 아니라 서버 쪽 사정이다.
//
//	tls_probe version
//	tls_probe cert [-alg=ecdsa|mldsa65] -hosts=localhost,127.0.0.1 DIR    DIR/ca.pem, cert.pem, key.pem (0644)
//	tls_probe serve -addr=127.0.0.1:4433 -groups=X25519MLKEM768,X25519 -cert=PATH -key=PATH
//	tls_probe connect -groups=X25519MLKEM768 [-ca=PATH | -tofu=PATH] -servername=NAME [-wait=10s] HOST:PORT
//	tls_probe listeners -ports=8443,9443 [-wait=10s]
//
// connect는 "key: value" 줄(probe, target, offered, trust, result, protocol, group, cipher, cert_sig, cert_key,
// cert_chain, cert_not_after(RFC 3339 UTC), error)을 찍고, 핸드셰이크가 되면 0, 안 되면 1, 사용법 오류면 2로 끝난다.
//
// 신뢰: -ca도 -tofu도 없으면 시스템 신뢰 저장소(RootCAs nil)와 -servername으로 서버 인증서를 검증한다("trust: system").
// -ca=PATH는 그 CA만 믿는다("trust: ca-file"). 인증서 검증이 실패하면 error 줄이 "certificate verification failed: "로
// 시작한다(그때 협상 그룹은 재지 못한 것이고, 읽는 쪽은 이것을 거부나 고전 협상으로 읽으면 안 된다).
//
// -tofu=PATH: 더 약한 신뢰라 명시적으로 고를 때만 쓴다. CA 파일을 구할 수 없을 때(서비스가 실행 중에 자기 CA를 만드는 경우) 쓴다. 먼저 인증서 사슬만 읽는
// 접속을 한 번 하고(이 접속은 판정에 쓰지 않는다), 사슬의 마지막 인증서를 PATH에 PEM으로 쓴 뒤, 그 인증서를 신뢰
// 앵커로 삼아 제대로 검증하는 두 번째 접속으로 판정한다. "trust: tofu ca_spki_sha256=..." 줄이 남는다.
// 사슬 읽기 접속은 제시 그룹에 고전 그룹을 더해 보낸다(하이브리드 전용 서버에 고전을 제시하는 판정에서도 사슬은 받아야 하므로).
//
// listeners는 리눅스 /proc을 읽어 포트마다 듣는 소켓과 프로세스를 찍는다(PQ-Proof 그대로, 이 오프라인판에서는 쓰지 않는다).
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const version = "0.6.0"

// 읽는 쪽(pqlite/tlsprobe.py)이 이 앞머리로 '검증 실패라 협상을 재지 못함'을 거부·실패와 가른다
const verifyFailed = "certificate verification failed: "

var groupNames = map[string]tls.CurveID{
	"X25519MLKEM768":     tls.X25519MLKEM768,
	"SecP256r1MLKEM768":  tls.SecP256r1MLKEM768,
	"SecP384r1MLKEM1024": tls.SecP384r1MLKEM1024,
	"X25519":             tls.X25519,
	"P-256":              tls.CurveP256,
	"P-384":              tls.CurveP384,
	"P-521":              tls.CurveP521,
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Printf("tls_probe %s (%s)\n", version, runtime.Version())
		return
	case "cert":
		err = cert(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	case "connect":
		os.Exit(connect(os.Args[2:]))
	case "listeners":
		os.Exit(listeners(os.Args[2:]))
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls_probe:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tls_probe version | cert | serve | connect | listeners (see the source)")
	os.Exit(2)
}

func parseGroups(s string) ([]tls.CurveID, error) {
	var ids []tls.CurveID
	for _, name := range strings.Split(s, ",") {
		id, ok := groupNames[name]
		if !ok {
			return nil, fmt.Errorf("unknown group %q", name)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func cert(args []string) error {
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	hosts := fs.String("hosts", "localhost,127.0.0.1", "comma-separated DNS names and IPs for the leaf")
	alg := fs.String("alg", "ecdsa", "ecdsa(P-256) 또는 mldsa65(CA와 리프 모두 ML-DSA-65)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
	}
	dir := fs.Arg(0)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	newKey := func() (any, any, error) { // (개인키, 공개키)
		switch *alg {
		case "ecdsa":
			k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return k, &k.PublicKey, nil
		case "mldsa65":
			k, err := mldsa.GenerateKey(mldsa.MLDSA65())
			if err != nil {
				return nil, nil, err
			}
			return k, k.PublicKey(), nil
		}
		return nil, nil, fmt.Errorf("unknown -alg %q", *alg)
	}
	now := time.Now()
	caKey, caPub, err := newKey()
	if err != nil {
		return err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tls_probe test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		return err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, pub, err := newKey()
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tls_probe test server"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, h := range strings.Split(*hosts, ",") {
		if ip := net.ParseIP(h); ip != nil {
			leaf.IPAddresses = append(leaf.IPAddresses, ip)
		} else {
			leaf.DNSNames = append(leaf.DNSNames, h)
		}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, pub, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	// 일부러 모두 읽기(0644): 한 번 쓰고 버리는 참조 서버용 시험 재료이고, 컨테이너 안 다른 사용자도 읽어야 한다.
	for name, block := range map[string]*pem.Block{
		"ca.pem":   {Type: "CERTIFICATE", Bytes: caDER},
		"cert.pem": {Type: "CERTIFICATE", Bytes: leafDER},
		"key.pem":  {Type: "PRIVATE KEY", Bytes: keyDER},
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o644); err != nil { // WriteFile's mode is cut by the umask
			return err
		}
	}
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:4433", "listen address")
	groups := fs.String("groups", "X25519MLKEM768,X25519", "groups to accept, in order")
	certFile := fs.String("cert", "", "certificate (PEM)")
	keyFile := fs.String("key", "", "private key (PEM)")
	fs.Parse(args)
	ids, err := parseGroups(*groups)
	if err != nil {
		return err
	}
	pair, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", *addr, &tls.Config{Certificates: []tls.Certificate{pair}, CurvePreferences: ids,
		MinVersion: tls.VersionTLS13})
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			c.(*tls.Conn).Handshake()
		}(c)
	}
}

// dial은 거절된 연결을 wait 동안 다시 시도한다(서비스가 아직 뜨는 중일 때).
func dial(target string, wait time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(wait)
	for {
		raw, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err == nil || !errors.Is(err, syscall.ECONNREFUSED) || time.Now().After(deadline) {
			return raw, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// tofuFetch는 판정하지 않는 접속으로 서버가 보낸 사슬의 마지막 인증서를 읽어 path에 쓴다.
// 이 접속만 검증을 끈다. 판정은 이 인증서를 신뢰 앵커로 다시 붙는 접속이 한다.
func tofuFetch(target, serverName, path string, ids []tls.CurveID, wait time.Duration) (*x509.Certificate, error) {
	raw, err := dial(target, wait)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	offer := append([]tls.CurveID{}, ids...)
	for _, id := range []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384} {
		found := false
		for _, x := range offer {
			found = found || x == id
		}
		if !found {
			offer = append(offer, id)
		}
	}
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: serverName, CurvePreferences: offer})
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("tofu fetch: %w", err)
	}
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("tofu fetch: no certificate")
	}
	anchor := chain[len(chain)-1]
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw}), 0o644); err != nil {
		return nil, err
	}
	return anchor, nil
}

func keyName(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	case *mldsa.PublicKey:
		return k.Parameters().String()
	}
	return c.PublicKeyAlgorithm.String()
}

func connect(args []string) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	groups := fs.String("groups", "X25519MLKEM768", "groups to offer, in order")
	caFile := fs.String("ca", "", "CA certificate (PEM) the server certificate must chain to")
	tofu := fs.String("tofu", "", "명시적 TOFU(더 약함): 사슬의 마지막 인증서를 이 경로에 쓰고 그것으로 검증")
	serverName := fs.String("servername", "localhost", "server name to send and verify")
	wait := fs.Duration("wait", 10*time.Second, "keep retrying a refused connection this long")
	if fs.Parse(args) != nil || fs.NArg() != 1 || (*caFile != "" && *tofu != "") {
		fmt.Fprintln(os.Stderr, "usage: tls_probe connect -groups=G1,G2 [-ca=PATH | -tofu=PATH] [-servername=NAME] [-wait=10s] HOST:PORT")
		return 2
	}
	target := fs.Arg(0)
	fmt.Printf("probe: tls_probe %s (%s)\ntarget: %s\noffered: %s\n", version, runtime.Version(), target, *groups)
	fail := func(err error) int {
		fmt.Printf("result: failed\nerror: %s\n", strings.ReplaceAll(err.Error(), "\n", " "))
		return 1
	}
	ids, err := parseGroups(*groups)
	if err != nil {
		return fail(err)
	}
	switch {
	case *tofu != "":
		anchor, err := tofuFetch(target, *serverName, *tofu, ids, *wait)
		if err != nil {
			return fail(err)
		}
		spki := sha256.Sum256(anchor.RawSubjectPublicKeyInfo)
		fmt.Printf("trust: tofu ca_spki_sha256=%s self_signed=%v\n", hex.EncodeToString(spki[:]),
			anchor.CheckSignatureFrom(anchor) == nil)
		*caFile = *tofu
	case *caFile != "":
		fmt.Println("trust: ca-file")
	default:
		fmt.Println("trust: system")
	}
	var roots *x509.CertPool // nil: Go가 시스템 신뢰 저장소를 쓴다
	if *caFile != "" {
		caPEM, err := os.ReadFile(*caFile)
		if err != nil {
			return fail(err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return fail(errors.New("no certificate in " + *caFile))
		}
	}
	conf := &tls.Config{RootCAs: roots, ServerName: *serverName, CurvePreferences: ids}
	raw, err := dial(target, *wait)
	if err != nil {
		return fail(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	conn := tls.Client(raw, conf)
	if err := conn.Handshake(); err != nil {
		var verr *tls.CertificateVerificationError
		if errors.As(err, &verr) {
			return fail(fmt.Errorf("%s%w", verifyFailed, verr.Err))
		}
		return fail(err)
	}
	st := conn.ConnectionState()
	fmt.Printf("result: connected\nprotocol: %s\ngroup: %s\ncipher: %s\n", tls.VersionName(st.Version), groupName(st.CurveID),
		tls.CipherSuiteName(st.CipherSuite))
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		fmt.Printf("cert_sig: %s\ncert_key: %s\ncert_chain: %d\ncert_not_after: %s\n", leaf.SignatureAlgorithm, keyName(leaf),
			len(st.PeerCertificates), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return 0
}

func groupName(id tls.CurveID) string {
	for name, v := range groupNames {
		if v == id {
			return name
		}
	}
	return id.String()
}

type socket struct {
	addr  string
	port  int
	uid   string
	inode string
}

// listening reads the listening TCP sockets from /proc/net/tcp and /proc/net/tcp6.
func listening() []socket {
	var out []socket
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) < 10 || f[3] != "0A" { // 0A: TCP_LISTEN
				continue
			}
			host, port, ok := strings.Cut(f[1], ":")
			p, err := strconv.ParseUint(port, 16, 16)
			ip, ipErr := procIP(host)
			if !ok || err != nil || ipErr != nil {
				continue
			}
			out = append(out, socket{addr: ip.String(), port: int(p), uid: f[7], inode: f[9]})
		}
	}
	return out
}

// procIP decodes an address from /proc/net/tcp*: 32-bit words in the kernel's (little-endian) order.
func procIP(h string) (net.IP, error) {
	if len(h) != 8 && len(h) != 32 {
		return nil, fmt.Errorf("bad address %q", h)
	}
	ip := make(net.IP, len(h)/2)
	for w := 0; w < len(h)/8; w++ {
		v, err := strconv.ParseUint(h[w*8:w*8+8], 16, 32)
		if err != nil {
			return nil, err
		}
		for b := 0; b < 4; b++ {
			ip[w*4+b] = byte(v >> (8 * b))
		}
	}
	return ip, nil
}

// holders maps socket inodes to the pids that hold them, from /proc/*/fd.
func holders() map[string][]int {
	out := map[string][]int{}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		fds, _ := os.ReadDir(filepath.Join("/proc", p.Name(), "fd"))
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join("/proc", p.Name(), "fd", fd.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inode := link[len("socket:[") : len(link)-1]
				out[inode] = append(out[inode], pid)
			}
		}
	}
	return out
}

// oneWord replaces anything but printable ASCII other than a space with '?', so a process cannot
// add or end a line through the name of the file it runs from.
func oneWord(s string) string {
	return strings.Map(func(r rune) rune {
		if r > ' ' && r < 0x7f {
			return r
		}
		return '?'
	}, s)
}

func listeners(args []string) int {
	fs := flag.NewFlagSet("listeners", flag.ContinueOnError)
	ports := fs.String("ports", "", "comma-separated TCP ports that must be listening")
	wait := fs.Duration("wait", 10*time.Second, "wait this long for every port to listen")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *ports == "" {
		fmt.Fprintln(os.Stderr, "usage: tls_probe listeners -ports=P1,P2 [-wait=10s]")
		return 2
	}
	var want []int
	for _, s := range strings.Split(*ports, ",") {
		p, err := strconv.Atoi(s)
		if err != nil || p < 1 || p > 65535 {
			fmt.Fprintln(os.Stderr, "tls_probe: bad port", s)
			return 2
		}
		want = append(want, p)
	}
	deadline := time.Now().Add(*wait)
	var socks []socket
	var missing []int
	for {
		socks, missing = listening(), nil
		for _, p := range want {
			found := false
			for _, s := range socks {
				found = found || s.port == p
			}
			if !found {
				missing = append(missing, p)
			}
		}
		if len(missing) == 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	held := holders()
	var lines []string
	for _, s := range socks {
		pids := held[s.inode]
		if len(pids) == 0 {
			pids = []int{0}
		}
		for _, pid := range pids {
			exe := "?"
			if pid != 0 {
				if e, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
					exe = oneWord(e)
				}
			}
			lines = append(lines, fmt.Sprintf("listen: %s uid=%s inode=%s pid=%d exe=%s",
				net.JoinHostPort(s.addr, strconv.Itoa(s.port)), s.uid, s.inode, pid, exe))
		}
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Println(l)
	}
	for _, p := range missing {
		fmt.Printf("missing: %d\n", p)
	}
	if len(missing) > 0 {
		return 1
	}
	return 0
}
