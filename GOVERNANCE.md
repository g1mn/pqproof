# Governance

PQ-Proof is maintainer-led. This page says who decides, how changes get into `main`, and how the project keeps going if a maintainer is no longer available. The people who hold each role are listed in [MAINTAINERS.md](MAINTAINERS.md).

## Roles

| Role | Who | Responsibilities |
|---|---|---|
| Lead maintainer | named in MAINTAINERS.md | Final decisions. Release tags (`v*`) and PyPI publishing. Security reports ([SECURITY.md](SECURITY.md)) and Code of Conduct reports ([CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)). Repository settings and the project site. |
| Maintainer | named in MAINTAINERS.md | Reviews and approves pull requests, triages issues and gives first replies. Can merge a pull request that has an approval and passing checks. |
| Contributor | anyone | Opens issues, discussions and pull requests under [CONTRIBUTING.md](CONTRIBUTING.md). |

## How changes are accepted

- A change to `main` goes through a pull request. It needs one approval from a maintainer other than the last person who pushed to it, and the required checks (`lint` and `test`) must pass. Repository rules enforce this.
- The lead maintainer can bypass those rules. The bypass is for release commits (version, changelog and site) and for urgent security fixes. Everything else goes through a pull request like any other change.
- A change that can move a verdict (a rule file, see "Changing a rule" in CONTRIBUTING.md) also needs the lead maintainer's approval and a CHANGELOG entry with its verdict impact.
- Only the lead maintainer can create release tags. The release workflow publishes to PyPI from those tags only.

## How decisions are made

Questions are settled in the issue, pull request or discussion where they come up. When people do not agree, the lead maintainer decides and writes the reason in that thread. Larger changes of direction go into [ROADMAP.md](ROADMAP.md) through a pull request, so they are reviewed like code.

## Becoming a maintainer

A contributor with a record of reviewed contributions can be invited by the lead maintainer. The invitation is a pull request that adds the person to MAINTAINERS.md. A maintainer who wants to step down opens a pull request that removes their name.

## Continuity

The project has to be able to go on within a week if any one person is no longer available.

- Maintainers can create and close issues, review pull requests and merge approved ones without the lead maintainer.
- The lead maintainer has named a maintainer as the successor of the GitHub account that owns this repository, so that person can take over the repository and its settings.
- A maintainer is also an owner of the `pqproof` project on PyPI, so publishing can be moved to a new repository if needed.
- A release does not need the site generator. Set the version and the CHANGELOG section, then edit the `data-build` block and the visible version lines in `docs/index.html` by hand. `python3 -I tests/version_policy.py --site-only` lists every value that still differs. Tag `vX.Y.Z` on `main` when CI passes.

## Changing this document

Open a pull request. Changes to this page need the lead maintainer's approval.
