"""Fuzz target: pqlite.receipt.loads_strict reads receipt.json from an evidence folder someone else made (`--verify`).
Its contract is that bad input raises ValueError only (bad UTF-8, BOM, duplicate keys, NaN, trailing bytes, deep nesting).
Runs under ClusterFuzzLite (.clusterfuzzlite/); locally: PYTHONPATH=. python3 tests/fuzz/evidence_json_fuzzer.py -runs=100000"""
import sys

import atheris

with atheris.instrument_imports():
    from pqlite import receipt


def test_one_input(data):
    try:
        receipt.loads_strict(data)
    except ValueError:
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
