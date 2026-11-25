# Configuration

Settings are environment variables, the same for `pqproof` and `bash prove.sh`. `pqproof --env` prints the list with the Korean notes. The first stderr line of a run shows the settings it applied, and a variable one letter off a setting name (`REQUIRE_REVEIW`, `TLS_TARGET`) or an unknown `PQPROOF_` name gets a warning.

| Setting | Default | What it does |
|---|---|---|
| `OUT` | `./proof-out-YYYYMMDD-HHMMSS` | output folder; an existing one stops the run |
| `ALLOW` | `<W>/notes/unconverted.json` when the original is `<W>/orig` | allowlist file, or `none` ([allowlist.md](allowlist.md)) |
| `REQUIRE_REVIEW` | `0` | `1`: an allowlist entry without a person's review, or an unused entry, fails the run. Recommended for real reviews |
| `EXPECT` | `kem,sig` | what the fixed tree must use: `kem` (ML-KEM), `sig` (ML-DSA), `tls` (hybrid TLS), `cert` (ML-DSA certificate), or `none`. `PROFILE` says which sizes count |
| `PROFILE` | `nist-cat3` | algorithm profile from `scan/profiles.json`: `nist-cat3` counts ML-KEM-768 or 1024 and ML-DSA-65, 87 or SLH-DSA 192, 256 (FIPS 205); `cnsa2` counts only ML-KEM-1024 and ML-DSA-87 and offers `SecP384r1MLKEM1024` to TLS targets; `kpqc` also counts SMAUG-T, NTRU+, HAETAE and AIMer |
| `SCOPE` | `all` | `kex`: judge key exchange only; signatures and encryption are listed as out of scope |
| `FAIL_ON_REVIEW` | `0` | `1`: a pass with a check that needs review exits 5 instead of 0. The verdict stays pass |
| `REQUIRE_RESOLVED` | `0` | `1`: key material the scanner could not open (an encrypted PKCS#8 key, a keystore without its password) or a public-key API whose algorithm name it could not read fails `a-cbom` |
| `EXPECT_FROM` | `names` | `api`: count `c-expect` from post-quantum API calls (Java JCA and BouncyCastle, Node `generateKeyPair`, Go `crypto/mlkem`) instead of lines that name the algorithm |
| `REVIEW_MAX_AGE_DAYS` | none | a `reviewed_at` older than this many days counts as not reviewed |
| `MAX_FILE_MIB` | `1` | size limit for `scan.py`, the weakening check and the allowlist check. Code and config files over it are listed and make `a-input` need review |
| `CLASSIC` | `allow` | `deny`: a TLS target must refuse an old client offering only X25519 and P-256 |
| `EXCLUDE` | none | run-data globs such as `data/** *.db *.log`. Code, config and build files are never excluded |
| `RECON` | `<W>/notes/recon.json` | reads `DATA_DIR` and the app root, to exclude a data folder inside the app |
| `TLS_TARGETS` | none | addresses of the running fixed service (see below) |
| `TLS_TARGETS_ORIG` | none | addresses of the original service, recorded as a baseline only |
| `TLS_VIA` | `host` | `container:<name>` measures inside a container's network namespace |
| `PROBE_BIN_DIR` | `bin/`, then the user cache | folder with `tls_probe-<os>-<arch>` |
| `OPENSSL` | the first OpenSSL 3.5 or later found, else the first OpenSSL | used as given, even below 3.5 |
| `RESIDUE` | `scan/residue.sh` | a service-specific copy with site rules; the run is then named `<ruleset>+modified` |
| `CBOM_SCAN` | `scan/cbom-scan.sh` | another CBOM scanner (also `+modified`) |
| `EXTRA_EV` | none | other files to store with the evidence, such as a test log |
| `EV_NAME` | `<output folder>.txt` | name of the file where you save the console output yourself (PQ-Proof does not write it); recorded as `ev` in `deck.json` and, when set, in `tables/report.md` |

Tool settings: `PYTHON` (the interpreter `prove.sh` uses), `STRICT=1` (tests fail on any skipped case), `PQPROOF_HOME` (another checkout of the tool files).

## Work folder

A migration pipeline can keep everything in one folder `<W>`: `<W>/orig` (original), `<W>/repo` (fixed), `<W>/notes/unconverted.json` (allowlist), `<W>/notes/recon.json`, `<W>/evidence/`. With the original at `<W>/orig`, the run finds the notes by itself and writes to `<W>/evidence/proof-YYYYMMDD-HHMMSS`.

```bash
W=/work/billing
EXCLUDE='data/** *.db *.log' REQUIRE_REVIEW=1 pqproof "$W/orig" "$W/repo"
```

## TLS targets

`b-tls` needs a running server. Build the probe once (static Go binaries, nothing downloaded), start the fixed service, and pass its address:

```bash
pqproof build-probe      # or, from a clone: bash build-probe.sh
EXPECT=kem,sig,tls TLS_TARGETS="127.0.0.1:8443@localhost#/abs/path/ca.pem" pqproof orig/ fixed/
```

A target is `host:port`, then optionally `@servername`, then optionally `#/absolute/path/ca.pem` or `#tofu`. The probe always verifies the server certificate, and the target says what it trusts:

| Target | Trust (`trust` in the evidence) | Server name checked when `@servername` is left out |
|---|---|---|
| `host:port` | the system trust store (`system`), the default from 0.8.0 | the host of the address |
| `host:port#/abs/ca.pem` | only that CA (`ca-file`) | `localhost` |
| `host:port#tofu` | the last certificate the server sends, taken on first use (`tofu`) | `localhost` |

Trust on first use is weaker: the probe first reads the chain without checking it and then verifies against the last certificate it got, so it shows what the server negotiates but not that the server is the one you meant. Use it only when you cannot get the CA, for example a service that makes its own CA at start-up, and keep `#tofu` out of a pipeline that should prove who answered. Before 0.8.0 a target without a CA was always trusted on first use. A certificate that does not verify (unknown CA, wrong name, expired) is not a pass and not a refusal: the probe could not measure that handshake, so `b-tls` is undecided and names the target and the verification error. Give the CA, fix the server name with `@servername`, or opt in to `#tofu`. The two handshakes are judged one by one, so a failure measured before the certificate is checked still fails: a server that refuses the hybrid-only offer fails even when the old-client handshake then fails verification. In container mode (`TLS_VIA=container:<name>`) the system trust store is the one in the target container's image: the probe clears `SSL_CERT_FILE` and `SSL_CERT_DIR`, but the files in the image are chosen by whoever built it, which is the tree under test, so the `b-tls` line says so; give the CA file there when that matters. Before it measures your server, the probe tests itself against two local reference servers, one hybrid and one X25519-only. If either control comes out wrong, the run is undecided. On the host with OpenSSL 3.5 or later, the tool repeats the hybrid-only handshake with `openssl s_client` and compares the group. That handshake verifies the certificate too (`-verify_return_error` with `-verify_hostname`, or `-verify_ip` for an address), against the same CA file, the `#tofu` anchor or OpenSSL's default trust paths. On macOS `tls_probe` uses the system keychain and OpenSSL uses its own `cert.pem`, so a root added only to the keychain verifies in one and not the other; the run is then undecided (OpenSSL disagrees) and the fix is to give the CA file. On macOS a target checked against the system trust store (`trust: system`) is verified by the operating system (Go's `crypto/x509` calls `SecTrustEvaluateWithError` and leaves network fetching on), which can connect to other addresses to fetch a missing intermediate certificate or revocation data; give the CA file (`#/abs/path/ca.pem`) to keep the run to the target address.

PQ-Proof 0.8.0 needs `tls_probe` 0.6.0 (`tls_probe version` prints it); 0.5.0 cannot verify against the system trust store. A probe built or downloaded for an earlier release stays in `~/.cache/pqproof/bin`, a clone's `bin/` or your `PROBE_BIN_DIR` after an upgrade, so rebuild it or replace the files. On a version mismatch `pqproof doctor` warns, `pqproof` with `TLS_TARGETS` stops before the run, and `prove.sh` leaves `b-tls` undecided without measuring.

Without Go, download `tls_probe-<os>-<arch>` and `SHA256SUMS` from the GitHub release into one folder, run `shasum -a 256 -c --ignore-missing SHA256SUMS` there, and set `PROBE_BIN_DIR` to it. `gh attestation verify <file> --repo g1mn/pqproof` shows that a binary came from the release workflow.
