#!/bin/bash -eu
# Bundle each tests/fuzz/*_fuzzer.py with the pqlite package it imports (no packages are downloaded).
export PYTHONPATH="$SRC/pqproof"
for fuzzer in "$SRC"/pqproof/tests/fuzz/*_fuzzer.py; do
  compile_python_fuzzer "$fuzzer"
done
