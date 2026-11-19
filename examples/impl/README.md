# Implementation check example harness

`pqproof impl` checks a KpqC implementation (SMAUG-T, NTRU+, HAETAE, AIMer) against pinned reference KAT versions. PQ-Proof writes a question sheet and compares your answers. It never builds or runs your code. `kpqc_harness.py` is one way to write the answers: it loads shared libraries that export the NIST API through Python `ctypes` (standard library only).

```bash
pqproof impl prompt --param smaug-t/mode3 --param haetae/mode3 -o prompt.json
python3 -I kpqc_harness.py prompt.json answers.json \
  --lib smaug-t/mode3=./libsmaugt-mode3.dylib --lib haetae/mode3=./libhaetae-mode3.dylib
pqproof impl judge answers.json
```

- KEM libraries export `crypto_kem_keypair`, `crypto_kem_enc` and `crypto_kem_dec`; signature libraries export `crypto_sign_keypair`, `crypto_sign_signature` and `crypto_sign_verify` with a context string (lengths are `size_t`).
- The optional derand items also need `randombytes_init` from the KAT DRBG (`rng.c` of the reference KAT program). Without it the harness answers decaps and verify only, and the judge may not be able to tell an old version from the latest one (needs review).
- The harness runs the library, including its initialization code. Use it on your own builds and run other people's binaries in a container or a VM.
- A full PQCgenKAT `.rsp` from your build works too: `pqproof impl judge PQCkemKAT_smaugt_mode3.rsp`.

The result is a match with a reference version's KAT (version name and `.rsp` SHA-256 in `scan/kat-kpqc.json`), not a conformance test or a certification.

## NIST PQC through pq-verify

NIST PQC libraries (ML-KEM, ML-DSA, SLH-DSA) go through pq-verify, a separate tool you install in its own virtual environment. PQ-Proof calls it without a shell and keeps its report in the same receipt (check `i-nist`):

```bash
PQ_VERIFY=/path/to/venv/bin/pq-verify pqproof impl judge answers.json --pq-verify "--audit-kem ./libmlkem768.so ML-KEM-768"
```

pq-verify loads and runs that library, so the container advice above applies to it too. Leave out `answers.json` to run only the pq-verify audit.
