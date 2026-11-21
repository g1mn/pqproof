"""Fuzz target: pqlite.impl.parse_input reads the answer file a user hands to `pqproof impl judge` (answer JSON or a
PQCgenKAT .rsp). Its contract is that it never raises: a malformed file comes back with a "problem" string instead.
Runs under ClusterFuzzLite (.clusterfuzzlite/); locally: PYTHONPATH=. python3 tests/fuzz/answer_fuzzer.py -runs=100000"""
import sys

import atheris

with atheris.instrument_imports():
    from pqlite import impl


def test_one_input(data):
    out = impl.parse_input(data)
    assert out["kind"] in ("response", "rsp", None), out["kind"]
    assert out["problem"] is None or isinstance(out["problem"], str), out["problem"]


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
