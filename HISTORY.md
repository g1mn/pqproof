# History

I built PQ-Proof for the finals of 2026년 양자내성암호 전환 해커톤 (2026 Post-Quantum Cryptography Transition Hackathon), organized by the Ministry of Science and ICT and hosted by KISA. I won 대상 (Grand Prize), given as the 부총리상 (Deputy Prime Minister's Award). The English names are my translations. An AI coding agent made the code changes, and PQ-Proof (then just `prove.sh`) was the completion check in its pipeline. This repository is based on the version that ran in the finals, minus contest material, local paths and contest-only report tables. I fixed two flaws found in testing after the finals and closed two gaps that a review of those fixes turned up; [Changes since the finals](#changes-since-the-finals) lists what moved. This is a participant's own tool; the organizers have not reviewed or endorsed it.

## Use in the finals

In the finals, `prove.sh` was the completion check at the end of my migration pipeline. On all five tasks the first run failed and the last run passed. On four of them the fixed code did not change between those runs: the agent added or widened allowlist entries, each with a reason, and the verdict turned to pass. None of those entries had a review record, because the review fields came after the finals. That is why `r-allow` exists. The organizers' own grading made the final call.

I wanted the fixing and the judging kept apart. A coding agent changes code quickly, and it can also write changes that look finished when they are not. So the step that says "finished" has no model in it: the same inputs give the same verdict. The evidence hash still changes from run to run, because the evidence also records when and where the run happened.

## Changes since the finals

Three things changed after the finals: one new check, and fixes for two flaws I found while re-checking the tool. Both flaws were already in the finals version. A review of the first fixes then found a gap in each, and I closed both. The 0.1.0 packaging, SARIF output, Action, versioning and test changes are listed in [CHANGELOG.md](CHANGELOG.md), and the rules as they stand are in [DESIGN.md](DESIGN.md).

### Review record (`r-allow`)

`r-allow` shows whether a person read each allowlist entry (see [DESIGN.md](DESIGN.md#allow-rules)). It changes the verdict only under `REQUIRE_REVIEW=1`.

### Unused allowlist entries

You write the allowlist for the fixed tree, but it applies to any tree you run it on. An entry that matched no classical line in the fixed tree used to stay in the list as "unused" with no warning. Run against the original, the same list let that entry allow the classical lines in its range, and in one case it hid every blocking location of the original. A key-generating line inside an allowed range showed up only as "needs review" in the check rows.

The tool now also resolves the list against the original and records, per entry, how many classical lines it covers in each tree (`lines_fixed`, `lines_orig`). It warns about every unused entry, names the original lines that entry would cover, and marks `r-allow` as needs review. Under `REQUIRE_REVIEW=1` an unused entry fails the run. The verdict line also counts write paths left inside allowed ranges, and `--verify` checks all of these counts against the entries.

The lines an unused entry would hide do not go back to being blocking locations. Within one run they sit in the original, which the tool never judges. If someone puts the original in the fixed slot, the entry matches lines there, and nothing in the list says which tree it was written for. So the tool flags the entry in the run where it is unused, and `REQUIRE_REVIEW=1` makes you delete it. In a unit test (`tests/test_allowlist.py`, masked case), deleting the unused entry makes the same tree fail and lists its blocking locations.

The first version of this fix missed one case. An entry that points to a file deleted from the fixed tree, or to lines past the end of a file that got shorter, is invalid there and allows nothing, so it only got a warning. In the original the same entry is valid and hides those lines, and with a review record on it the run passed even under `REQUIRE_REVIEW=1`. Such an entry now counts as unused whenever it covers classical lines in the original, and so does an entry that points only outside the tree or at excluded data files. `--verify` recounts this from each entry's status and `lines_orig`, and fails newer evidence when someone deletes its unused and write-path counts.

### One list of test paths

In the finals version, three places decided what a test path was. `cbom-scan.sh` marked twelve test and example folder names and test file patterns such as `*_test.go` as tests. `pqlite/scan.py`, the other scanner behind `a-cbom`, skipped only Java files under `src/test/`, `test/` or `tests/` or named `*Test`, and Go files named `*_test.go`. `residue.sh`, which `c-classic` and `c-expect` read, skipped only `src/test/`, `test/` and `tests/`. A Go test in `seal_test.go` that builds a P-256 key to check that it gets rejected passed `a-cbom` and failed `c-classic`. Now one file, `scan/test-paths.ere`, holds the rule, and `cbom-scan.sh`, `residue.sh`, `pqlite/scan.py` and the TLS signal check all read it.

My first version of the shared rule matched folder names such as `example` anywhere in the path. That made `src/main/java/com/example/`, the default Spring package, test code: classical Java left there passed, and a correct Java-only migration there failed `c-expect`. The file now has a second line, a main-source marker (`/src/main/`). When a path contains it, the tool matches only the part before the marker, so nothing under `src/main/` is a test path, while `tests/it/src/main/` still is. `examples/`, `samples/`, `spec/`, `fixtures/` and `mock(s)/` count only at the top of the tree. `test/`, `tests/`, `__tests__/` and `testdata/` count at any depth, and so do test file names.

Skipping more paths risks missing production code kept in a folder named like a test folder. Skipping fewer fails good migrations that test the rejection of old keys and pushes test code into the allowlist. The skipped lines stay visible: `c-classic` prints how many classical lines sit in test paths and where, `a-cbom` counts them apart, and the evidence keeps them. ML-KEM and ML-DSA lines in test paths do not count as PQC use.

### Effect on verdicts

A tree whose only classical lines sit in test paths used to fail `c-classic` and now passes. The shared rule moved `a-cbom` and `c-expect` as well. Compared with the finals version, `c-classic` and `c-expect` now also skip test file names (`*_test.go`, `*Test.java`, `test_*.py` and the like), `__tests__/`, `testdata/` and the top-level example folders. `a-cbom` now also skips Go files in `test/` and `tests/`, and Java and Go files in `__tests__/`, `testdata/` and the top-level example folders. For Python, Node and the other files that only `cbom-scan.sh` reads, an `examples/`, `samples/`, `spec/`, `fixtures/` or `mock(s)/` folder below the top of the tree no longer counts as tests. Below `src/main/` nothing counts as a test path for any check, not even a class named `*Test.java`, unless a test folder sits above `src/main/`.

On the eight practice tasks I wrote for rehearsal, the verdicts did not change, and the review fixes changed no verdict, check or count. One change does show up: a list whose entries are all unused now makes `r-allow` need review where it used to be not applicable. That happened on five rehearsal runs, and none of their verdicts moved.

## Words in the output



## 한국어 요약

- 본선에서 코드는 AI 코딩 에이전트가 고쳤고 이 도구는 그 흐름 끝에서 전환이 끝났는지 확인하는 단계였다. 다섯 과제 모두 첫 판정은 실패, 마지막 판정은 통과였다. 네 과제는 고친 코드를 그대로 둔 채 허용 목록 항목을 더하거나 범위를 넓혀 통과로 바뀌었고 그 항목에는 사람 확인 기록이 없다(확인 칸은 본선 뒤에 더했다). 그래서 `r-allow`를 더했다. 최종 판정은 주최 측 채점이 했다.
- 본선 뒤 바뀐 점은 셋이다. 하나는 새 검사이고 둘은 다시 점검하다 찾은 결함(본선판에도 있던 것)을 고친 것이다. 이 고침을 따로 검토해서 나온 빈틈 두 개도 막았다. (1) 허용 목록 사람 확인 검사 `r-allow`를 더했다. (2) 고친 판에서 고전 줄을 하나도 덮지 않는 허용 항목(안 쓰인 항목)이 있으면 경고한다. 이런 항목은 같은 목록을 원본에 대면 그 범위의 고전 줄을 가린다. 원본에서 그 항목이 덮는 줄 수는 증적에 남기고 판정은 그대로 두되 `r-allow`를 검토 필요로 바꾸며 `REQUIRE_REVIEW=1`이면 실패로 끝낸다. 허용 범위 안 쓰기 경로 수도 판정 옆에 적어 둔다. 가린 줄을 막는 위치로 되돌리지는 않았다. 한 번 실행할 때 가려지는 줄은 판정하지 않는 원본 쪽에 있고 원본을 고친 판 자리에 넣으면 그 항목이 쓰이는 항목이 되어 구별할 수 없어서다. 대신 안 쓰인 항목을 지우게 했고 단위 시험에서 지워 보면 원본의 막는 위치가 다시 나온다(`tests/test_allowlist.py` 가림 재현). 고친 판에서 지운 파일을 가리킨 항목처럼 고친 판에서는 무효인데 원본에서는 고전 줄을 덮는 항목도 안 쓰인 항목으로 센다. 처음 고친 판은 이런 항목에 경고만 남겨 사람 확인 칸이 있으면 `REQUIRE_REVIEW=1`에서도 통과했다. (3) 시험 경로 기준을 `scan/test-paths.ere` 한 곳으로 모았다. cbom-scan.sh, residue.sh, pqlite/scan.py, TLS 신호 검사가 모두 이 파일을 읽는다. 본선판은 세 곳이 따로 정했다. cbom-scan.sh는 시험·예제 폴더 열두 가지와 시험 파일 이름을 시험으로 봤지만 a-cbom의 Java·Go 행을 내는 pqlite/scan.py는 Java의 `src/test/`·`test/`·`tests/`·`*Test`와 Go의 `_test.go`만 뺐고 c-classic이 읽는 residue.sh는 `src/test/`·`test/`·`tests/`만 뺐다. 그래서 `_test.go` 같은 음성 시험이 c-classic에서만 실패했다. 처음 고친 판은 폴더 이름을 경로 어디서든 맞춰서 Spring 기본 패키지 `src/main/java/com/example/`이 통째로 시험이 됐다. 지금은 목록 둘째 줄의 본 소스 표시(`/src/main/`) 앞부분만 맞춰 보므로 `src/main/` 아래는 시험이 아니다. `examples/`·`samples/`·`spec/`·`fixtures/`·`mock(s)/`는 트리 맨 위 폴더일 때만 시험으로 본다. 시험 경로의 고전 줄은 줄마다 따로 세어 보이며 이 규칙은 c-classic뿐 아니라 a-cbom과 c-expect에도 똑같이 걸린다. 고전 줄이 시험 경로에만 있는 소스는 실패에서 통과로 바뀐다. 리허설용으로 직접 만든 연습 과제 여덟 개의 판정은 바뀌지 않았다. 안 쓰인 항목만 있는 목록이면 r-allow가 해당 없음에서 검토 필요로 바뀐다(리허설 5회, 판정은 그대로).
