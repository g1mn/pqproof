# sbom_extend.py: cyclonedx-py 가 만든 SBOM(휠만 깐 환경의 구성 목록)에 릴리스 심사에 필요한 것을 더한다(교차 리뷰 X63).
#   (1) pqproof 구성요소에 휠·sdist 파일의 SHA-256
#   (2) tls_probe 바이너리마다 구성요소(SHA256SUMS 의 해시, BUILDINFO 의 Go 버전·빌드 플래그·소스 해시)
#   (3) 실행 중에 부르는 바깥 프로그램(bash, openssl, keytool): 필수·선택과 요구 버전
#   python3 -I sbom_extend.py --bom pqproof-X.cdx.json --dist dist/ --probe-dir assets/ --probe-version 0.4.0
# 표준 라이브러리만 쓴다. 같은 입력이면 같은 출력(정렬해서 쓴다).
"""Add file hashes, the tls_probe binaries and the external programs PQ-Proof runs to the CycloneDX SBOM of the wheel."""
import argparse
import glob
import hashlib
import json
import os
import sys

EXTERNAL = (
    ("bash", "required", ">=3.2", "runs prove.sh, cbom-scan.sh and residue.sh (grep, awk, sed, find and the other POSIX tools too)"),
    ("openssl", "required", ">=3.5 recommended", "reads certificates and keys; 3.5 or later also runs the TLS cross-check"),
    ("keytool", "optional", "any JDK", "reads .jks and .p12 keystores; without it they are listed as not checked"),
)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_buildinfo(path):
    info = {"go": "", "flags": "", "source": []}
    with open(path, encoding="utf-8") as f:
        for line in f:
            key, _, value = line.rstrip("\n").partition(": ")
            if key == "source":
                info["source"].append(value)
            elif key in info:
                info[key] = value
    return info


def extend(bom, dist, probe_dir, probe_version):
    comps = bom.setdefault("components", [])
    me = next((c for c in comps if c.get("name") == "pqproof"), None)
    if me is None:
        raise SystemExit("the SBOM has no pqproof component")
    files = sorted(glob.glob(os.path.join(dist, "pqproof-*.whl")) + glob.glob(os.path.join(dist, "pqproof-*.tar.gz")))
    if not files:
        raise SystemExit(f"no wheel or sdist in {dist}")
    me["hashes"] = [{"alg": "SHA-256", "content": sha256(files[0])}]
    me.setdefault("properties", []).extend({"name": f"pqproof:file:{os.path.basename(p)}", "value": f"sha256:{sha256(p)}"}
                                           for p in files)
    refs = []
    sums = os.path.join(probe_dir, "SHA256SUMS")
    build = read_buildinfo(os.path.join(probe_dir, "BUILDINFO"))
    with open(sums, encoding="utf-8") as f:
        for line in f:
            digest, _, name = line.strip().partition("  ")
            if not name.startswith("tls_probe-"):
                continue
            ref = f"pqproof-probe:{name}"
            refs.append(ref)
            comps.append({"type": "application", "bom-ref": ref, "name": name, "version": probe_version, "scope": "optional",
                          "description": "TLS probe for TLS_TARGETS live checks, built from probe/ with the Go standard library",
                          "hashes": [{"alg": "SHA-256", "content": digest}],
                          "properties": [{"name": "pqproof:go", "value": build["go"]},
                                         {"name": "pqproof:build-flags", "value": build["flags"]}]
                          + [{"name": "pqproof:source", "value": s} for s in build["source"]]})
    for name, scope, need, why in EXTERNAL:
        ref = f"pqproof-external:{name}"
        refs.append(ref)
        comps.append({"type": "application", "bom-ref": ref, "name": name, "scope": scope, "description": why,
                      "properties": [{"name": "pqproof:version-requirement", "value": need},
                                     {"name": "pqproof:provided-by", "value": "the host system, not this package"}]})
    if me.get("bom-ref"):
        deps = bom.setdefault("dependencies", [])
        entry = next((d for d in deps if d.get("ref") == me["bom-ref"]), None)
        if entry is None:
            entry = {"ref": me["bom-ref"], "dependsOn": []}
            deps.append(entry)
        entry["dependsOn"] = sorted(set(entry.get("dependsOn", [])) | set(refs))
        deps.extend({"ref": r, "dependsOn": []} for r in refs if not any(d.get("ref") == r for d in deps))
    return bom


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--bom", required=True)
    ap.add_argument("--dist", required=True)
    ap.add_argument("--probe-dir", required=True)
    ap.add_argument("--probe-version", required=True)
    a = ap.parse_args(argv)
    with open(a.bom, encoding="utf-8") as f:
        bom = json.load(f)
    extend(bom, a.dist, a.probe_dir, a.probe_version)
    with open(a.bom, "w", encoding="utf-8") as f:
        f.write(json.dumps(bom, indent=2, sort_keys=True) + "\n")
    print(f"SBOM: {len(bom['components'])} components -> {a.bom}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
