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
| `EV_NAME` | `<output folder>.txt` | file name recorded as `ev` in `deck.json` |

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

A target is `host:port`, then optionally `@servername` and `#/absolute/path/ca.pem`; without a CA the probe trusts the first certificate it sees. Before it measures your server, the probe tests itself against two local reference servers, one hybrid and one X25519-only. If either control comes out wrong, the run is undecided. On the host with OpenSSL 3.5 or later, the tool repeats the hybrid-only handshake with `openssl s_client` and compares the group.

Without Go, download `tls_probe-<os>-<arch>` and `SHA256SUMS` from the GitHub release into one folder, run `shasum -a 256 -c --ignore-missing SHA256SUMS` there, and set `PROBE_BIN_DIR` to it. `gh attestation verify <file> --repo g1mn/pqproof` shows that a binary came from the release workflow.
