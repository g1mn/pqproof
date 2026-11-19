# GitLab, Jenkins and SonarQube

- GitLab: `pqproof.gitlab-ci.yml` runs on merge requests. `sarif_to_codequality.py` turns the SARIF file into a Code Quality report, so remaining classical lines show up in the merge request. The script ships in the wheel, so the job finds it next to the installed package.
- Jenkins: `../jenkins/Jenkinsfile` records the SARIF file with the Warnings Next Generation plugin.
- SonarQube: import the SARIF file as external issues with `sonar.sarifReportPaths=pqproof.sarif` in the scanner properties.

All three read the allowlist from the base commit, as the GitHub example does, and keep the evidence folder as a build artifact. Exit codes: 0 pass, 1 fail, 2 usage or input error, 3 undecided, 4 tool error, 5 pass that needs review (only with `FAIL_ON_REVIEW=1`). More in [guide/ci.md](https://github.com/g1mn/pqproof/blob/main/guide/ci.md).
