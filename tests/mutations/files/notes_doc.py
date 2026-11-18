"""Notes on the migration.

The payload used to be wrapped with RSA-OAEP; it is ML-KEM-768 now.
"""
CAPSULE_BYTES = 1088  # replaces the old RSA-2048 block
