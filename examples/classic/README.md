# sealer (before)

A tiny sealer used by `prove.sh --selftest`. It wraps a data key for a recipient and signs the sealed record.
This is the version before the migration: RSA-OAEP key wrapping and ECDSA P-256 signatures, in Java and in Python.
Compare it with `../pqc`, the migrated version.

Written for this repository.
