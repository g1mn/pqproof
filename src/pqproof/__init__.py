"""PQ-Proof: check that a PQC migration is complete. The original and the converted tree are judged by the same rules,
and the run leaves a hashed evidence record (RFC 8785 + SHA-256). Offline, no AI calls.

The checking code itself is the shell and Python tool shipped as package data under pqproof/_tool (prove.sh, prove.py,
pqlite/, scan/). The console command `pqproof` runs it exactly like `bash prove.sh`.
"""
__version__ = "0.3.0"
