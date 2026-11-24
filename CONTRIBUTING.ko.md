# 기여 방법

[English](CONTRIBUTING.md) · 한국어

이슈와 풀 리퀘스트를 환영합니다. 보안 문제는 공개 이슈로 올리지 말고 [SECURITY.md](SECURITY.md)에 적힌 경로로 알려 주세요. 여기서는 모두 [행동 강령](CODE_OF_CONDUCT.md)을 따릅니다.

이슈와 풀 리퀘스트에는 3일 안에 첫 답을 드리려고 합니다. 질문과 아이디어는 [Discussions](https://github.com/g1mn/pqproof/discussions)에 남겨도 됩니다. 결정 방식과 리뷰하는 사람은 [GOVERNANCE.md](GOVERNANCE.md)와 [MAINTAINERS.md](MAINTAINERS.md)에 있습니다.

## 첫 기여

- `good first issue` 라벨이 붙은 이슈에서 하나를 고르세요. 이슈마다 고칠 파일과 확인 방법을 적어 두었습니다.
- 이슈를 맡으려면 그 이슈에 댓글을 남겨 주세요("I'll take this"면 충분합니다). 담당자로 지정해 드립니다. 2주 안에 풀 리퀘스트가 없으면 다른 분도 맡을 수 있게 다시 엽니다.
- 문서, 예제, 대응표, 시험은 규칙을 바꾸지 않습니다. `bash prove.sh --unit`을 돌리고, 대응표를 고쳤다면 `python3 -I tests/test_mappings.py`도 돌리세요.
- 규칙 파일('규칙 바꾸기'의 목록)을 고치면 규칙 묶음이 바뀌므로 그 절의 순서를 따라야 합니다.
- 어디에 넣을지 모르겠다면 먼저 이슈를 열어 주세요. 영어도 한국어도 괜찮습니다.
- 앞으로 할 일은 [ROADMAP.md](ROADMAP.md)에 있습니다.

## 로컬에서 확인하기

대부분의 변경은 이것으로 충분합니다. 건너뛴 시험은 통과와 따로 적히고, 여기서는 건너뜀이 실패가 아닙니다.

```bash
bash prove.sh --unit
python3 -I tests/test_mappings.py   # after a mapping change
```

CI는 모든 시험을 `STRICT=1`로 돌리고, 건너뛴 시험이 하나라도 있으면 실패합니다. 로컬에서 그렇게 하려면 네 가지가 더 필요합니다: `tls_probe`(`bash build-probe.sh`, Go 1.27 이상), `jsonschema`와 `SARIF_SCHEMA`에 둔 SARIF 스키마 파일과 `CDX_SCHEMA_DIR` 폴더에 둔 CycloneDX 1.6 스키마 파일 셋, 시험 라이브러리 둘을 갖춘 pq-verify(`bash tests/pqverify_targets.sh <new folder>`가 만들고 `PQPROOF_PQV_LIB=`와 `PQPROOF_PQV_BAD_LIB=` 줄을 찍습니다. 나머지는 `.github/workflows/ci.yml` 참고). 이것들이 없으면 `STRICT=1`은 건너뜀 때문에 exit 1로 끝나는데, 그게 정상입니다. 규칙을 바꾸기 전에는 전부 돌립니다.

```bash
STRICT=1 bash prove.sh --unit && STRICT=1 bash prove.sh --selftest \
  && python3 -I tests/mutations/run_mutations.py --strict --golden tests/golden/verdicts.json
cp -R . /tmp/pqproof-scan && (cd /tmp/pqproof-scan && bash scan/cbom-scan.sh --selftest)   # 시험용 키를 만들므로 사본에서 돌림
python3 -m pip install --require-hashes -r .github/requirements/lint.txt
ruff check . && shellcheck prove.sh build-probe.sh tests/pqverify_targets.sh tests/kpqc_targets.sh && shellcheck -S warning scan/residue.sh scan/cbom-scan.sh
go vet -C probe ./...
zizmor --offline --min-severity medium .github/workflows/ action.yml
```

매주 도는 `python3 -I tests/code_mutants.py --baseline`은 규칙 코드를 조금 바꿨을 때 동작 시험이 그 변화를 여전히 잡는지 봅니다.

## 저장소 구성

| 경로 | 내용 |
|---|---|
| `prove.sh`, `prove.py` | 진입점, 실행 순서, 표와 검증 증적 |
| `pqlite/` | 판정 규칙과 검사(`rules.py`), 코드 스캐너, TLS 약화 규칙, 탐침 출력 해석, 증적 작성과 검증, 허용 목록, 버전 |
| `scan/` | `cbom-scan.sh`(CBOM 스캐너, bash와 OpenSSL), `residue.sh`(기존 공개키 줄 세기), `test-paths.ere`(시험 경로 목록), `ruleset.json`(규칙 묶음 이름, 해시, 처음 실린 판, 판정 영향) |
| `src/pqproof/` | `pqproof` 명령, SARIF 변환기, 외부 프로그램 점검 |
| `schemas/` | `receipt.json`과 허용 목록의 JSON Schema(`tests/make_schemas.py`가 만듦) |
| `probe/`, `build-probe.sh` | `tls_probe` 소스(Go 표준 라이브러리)와 오프라인 빌드 스크립트 |
| `mappings/` | 기준 대응표: 공개 문서의 항목마다 그것을 확인하는 코드. `tests/test_mappings.py`가 검사합니다(`mappings/README.md` 참고) |
| `examples/` | 시험에 쓰는 전환 전후 트리, 허용 목록, GitHub·GitLab·Jenkins CI 예시 |
| `tests/` | 단위 시험, 변이 시험 묶음, golden 판정, 옛 증적, 퍼징 대상(`tests/fuzz/`), orders-edge 고정물 사본 |
| `guide/`, `DESIGN.md`, `HISTORY.md` | 사용법, 규칙과 증적 형식, 대회 이야기 |
| `action.yml`, `.github/`, `.clusterfuzzlite/` | GitHub Action, CI·Pages·릴리스·Scorecard·CodeQL·ClusterFuzzLite 워크플로, 해시로 고정한 도구 목록, Dependabot |
| `docs/` | GitHub Pages로 배포하는 사이트 |

코드 주석과 도구 출력은 한국어이고, 문서는 영어이며 DESIGN.md에 한국어 요약이 있습니다. README.md와 CONTRIBUTING.md에는 한국어 사본 README.ko.md와 CONTRIBUTING.ko.md가 있습니다. 둘은 같은 커밋에서 함께 고치세요. `tests/test_docs.py`가 두 판의 제목, 명령, 코드 표기, 표, 링크가 서로 맞는지 봅니다.

## 규칙 바꾸기

규칙 묶음은 `pqlite/version.py`의 `RULESET_FILES`에 든 파일입니다: `scan/cbom-scan.sh`, `scan/residue.sh`, `scan/test-paths.ere`, `scan/skip-dirs`, `scan/profiles.json`, `pqlite/scan.py`, `pqlite/verify.py`, `pqlite/allowlist.py`, `pqlite/rules.py`, `pqlite/skipdirs.py`, `pqlite/tlsprobe.py`, `pqlite/impl.py`, `scan/kat-kpqc.json`, 그리고 `scan/kat/`의 발췌입니다(규칙 묶음 3부터 14개). 건너뛸 폴더는 `scan/skip-dirs`에만 적습니다. 판정 상수나 패턴은 `prove.py`가 아니라 `pqlite/rules.py`에 둡니다. `prove.py`에 새 패턴 상수가 생기면 시험이 실패합니다. 규칙 묶음 5부터 주석은 규칙 묶음 해시에 들지 않습니다: 파이썬 주석, 셸 스캐너에서 따옴표와 heredoc 밖에 있는 주석 줄과 빈 줄, `scan/test-paths.ere`와 `scan/skip-dirs`의 `#` 줄이 그렇습니다. 셸 파일의 줄 끝 주석과 그 밖의 모든 바이트는 여전히 해시에 듭니다. 주석만 고쳤다면 `python3 -I -B pqlite/version.py --alias`를 돌리세요. 새 해시를 현재 규칙 묶음의 별칭으로 적고, 주석 말고도 바뀐 것이 있으면 거부합니다. 그 밖의 변경으로 돈 실행은 그 변경이 자기 규칙 묶음 이름을 얻기 전까지 `<current>+modified`로 적히므로, 이 파일들의 코드 린트 수정(CI가 `scan/cbom-scan.sh`와 `scan/residue.sh`에 shellcheck를 돌림)도 규칙 묶음 변경과 함께 들어가야 합니다.

규칙 ID나 값은 여러 파일에 있을 수 있습니다. 규칙을 새로 만들거나 바꿀 때는 이렇게 합니다.

1. 규칙 파일과, `tests/test_rule_sync.py`가 대조하는 사본을 함께 고칩니다: `pqlite/rules.py`의 `FAMILIES`, `WRITEOPS`, `ALLOWLINE`, `LEGACY_FILE`, `src/pqproof/sarif.py`의 `COUNTED_GEN`, `FAMILY_EN`, `RULES`.
2. `tests/test_rules.py`에 그 규칙이 잡아야 하는 행과, 잡으면 안 되는 비슷한 행을 하나씩 넣습니다. 행이 없는 규칙이나 패턴 대안은 이 시험에서 실패합니다. 알려진 빈틈을 고친 것이면 그 시험을 뒤집고 `KNOWN_GAPS`에서 번호를 지웁니다. `tests/code_mutants.py`가 가리키는 코드가 옮겨졌으면 그 검색 문자열도 고칩니다.
3. `python3 -I tests/mutations/run_mutations.py --strict --golden tests/golden/verdicts.json --diff-golden /tmp/moved.md`를 돌립니다. 판정, 검사 상태, 개수가 움직였고 그것이 의도한 변화라면 `--write-golden`으로 golden 파일을 다시 씁니다.
4. `scan/ruleset.json`에 규칙 묶음 항목을 더합니다(해시는 `python3 -I -B pqlite/version.py --ruleset-json`이 찍습니다). 새 이름, `since`(그 묶음을 처음 싣는 판), `verdict_impact`, `files`를 적고 `current`로 둡니다.
5. `CHANGELOG.md`의 `[Unreleased]`에 3단계의 표와 함께 "Verdict impact: yes"를 적습니다. 판정이 바뀌는 변경은 0.x 동안 MINOR 판으로 나갑니다(`tests/version_policy.py`가 지킵니다).
6. DESIGN.md의 표를 고칩니다.

규칙을 바꿀 때는 사이트 생성기가 필요 없습니다. 새 규칙 묶음의 `since`가 `__version__`보다 뒤인 동안 `tests/version_policy.py`는 사이트를 지금 판이 낸 규칙 묶음과 비교하고, KAT 목록과 증적 형식은 알림만 냅니다. 사이트는 판을 올릴 때 관리자가 다시 만듭니다('릴리스' 참고).

## 언어 더하기

탐지는 세 곳에 있습니다: `scan/residue.sh`의 이름 패턴(기존 공개키 줄 세기), `scan/cbom-scan.sh`의 CBOM 행, 구조 스캐너 `pqlite/scan.py`(Java, Go). `residue.sh` 패턴과 그 동작 행부터 시작하고, 그 언어의 시험 파일 이름이 시험 경로 규칙(`scan/test-paths.ere`)에 맞는지, 언어마다 다른 주석 판별이 맞는지 확인합니다. `residue.sh`는 파일 확장자마다 주석을 읽습니다(Python docstring과 줄 끝 `#`, 셸·YAML·TOML·Terraform·`sshd_config`의 `#`, C 계열 블록 주석). `cbom-scan.sh`는 맨 앞의 `#`, `--`, `;`를 그 기호를 쓰는 언어에서만 주석으로 읽고(C의 `#include`는 코드), `pqlite/rules.py`는 Go, JavaScript, Python, Java 행을 `pqlite/verify.py`의 토크나이저로 봅니다. 시험에 작은 전환 전후 짝을 더하세요. 이 하나하나가 모두 규칙 묶음 변경입니다.

## 서비스 전용 규칙

서비스는 `scan/residue.sh`를 복사해 `SITE` 규칙을 더하고 `RESIDUE=`로 넘겨 자기 규칙을 쓸 수 있습니다. 그 규칙의 `LEFT` 줄은 `c-classic`에 들어갑니다. 그 실행은 `<ruleset>+modified`로 적히고, 증적에는 실제로 돈 사본이 남습니다.

## 증적 형식

필드를 더하거나 빼거나 이름이나 뜻을 바꾸면 `pqlite/version.py`의 `format_version`을 올립니다. 그런 릴리스 전에는 `tests/golden/make_fixture.py`로 지금 판의 증적을 저장해 `tests/test_golden.py`가 계속 검사하게 하고, `python3 -I -B tests/make_schemas.py`로 스키마를 다시 만듭니다.

## 릴리스

1. `src/pqproof/__init__.py`의 `__version__`을 정하고, `CHANGELOG.md`의 `[Unreleased]`를 판정 영향을 적은 날짜 붙은 절로 바꿉니다.
2. 새 판에 맞춰 `docs/index.html`을 다시 만들고 판 변경과 함께 커밋합니다. README는 짧고 나머지는 모두 사이트에 있으므로, 사이트의 숫자, 예시 출력, 릴리스 항목, 한계, 자주 묻는 질문도 새 판에 맞게 검토합니다. 사이트 생성기는 이 저장소에 없고 관리자가 돌립니다. 사이트가 다른 판, 규칙 묶음, 증적 형식, KAT 목록을 가리키는 동안에는 `tests/version_policy.py`가 실패하므로 CI, 릴리스 워크플로, Pages 배포가 멈춥니다.
3. `main`을 push하고 CI를 기다린 뒤 그 커밋에 `vX.Y.Z` 태그를 답니다. 릴리스 워크플로는 CI를 다시 돌리고, `main`에 없는 태그는 받지 않습니다.
4. 릴리스 뒤에는 `examples/`의 고정값을 옮깁니다: `examples/github-actions/pqproof-sarif.yml`의 `g1mn/pqproof@<commit>` 줄(커밋 SHA와 주석), GitHub·GitLab·Jenkins 예시의 `pqproof==` 버전.

## 코드 형식

- 파이썬은 `pyproject.toml`의 ruff 규칙이 검사하는 PEP 8을 따르고, Python 3.9 이상을 대상으로 하며, 실행할 때는 표준 라이브러리만 씁니다(`dependencies = []`).
- 셸 스크립트는 bash 3.2에서 돌고, CI가 돌리는 방식의 ShellCheck를 통과해야 합니다.
- `probe/`의 Go 코드는 `gofmt`로 맞추고 `go vet`을 통과해야 합니다.
- CI의 `lint` 작업이 풀 리퀘스트마다 이 검사를 돌리고, 통과해야 병합됩니다.

## 풀 리퀘스트

판정이 바뀔 수 있는지 설명에 적어 주세요(템플릿이 묻습니다). 커밋은 작게, 시험과 함께 올려 주세요. 원칙: 새 기능과 버그 수정에는 `tests/` 아래 자동 시험을 함께 넣고, 큰 기능을 시험 없이 더하는 풀 리퀘스트는 병합하지 않습니다. 커밋 제목 끝에는 지금까지의 기록처럼 `Verdict impact: none`이나 `Verdict impact: yes`를 붙여, `git log`만 봐도 판정이 바뀔 수 있는 커밋이 보이게 합니다. 문서는 사용법이면 `guide/`에, 규칙과 형식이면 `DESIGN.md`에 둡니다.

같은 리뷰 지적이 두 번 나오면, 기억해 달라는 주석을 다는 대신 무엇을 고칠지 실패 메시지로 알려 주는 시험이나 린트 규칙으로 바꿉니다. 주석은 이유와 표준 근거(FIPS, RFC, KpqC 절)에 씁니다.
