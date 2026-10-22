# Contributing

blackbox_exporter uses GitHub to manage reviews of pull requests. These rules apply to every contribution. AI agents MUST follow [AGENTS.md](AGENTS.md).

* Read the [Prometheus contributor's guide](https://prometheus.io/docs/guides/contributing/#contributors-guide) in full.

* If you are a new contributor see: [Steps to Contribute](#steps-to-contribute)

* If you have a trivial fix or small improvement, go ahead and create a pull request. For a bugfix without an issue, put the reproduction steps in the PR description.

* If you plan to do something more involved, please open an issue that explains the problem and use case, and discuss it with maintainers before you raise the PR. When in doubt, open an issue first.

* Relevant coding style guidelines are the [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments) and the _Formatting and style_ section of Peter Bourgon's [Go: Best Practices for Production Environments](https://peter.bourgon.org/go-in-production/#formatting-and-style).

* Be sure to sign off on the [DCO](https://github.com/probot/dco#how-it-works).

* Report security issues privately as described in the [Prometheus security policy](https://prometheus.io/docs/operating/security/), not in public issues or PRs. The project acts on [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) results only, so reports from other scanners must include `govulncheck ./...` output showing the exporter is affected. An exposed exporter is not a security issue. Operators must secure its endpoints themselves with the web config (TLS, basic auth) and not expose it to the internet.

* Usage questions go to `#prometheus` on the [CNCF Slack](https://slack.cncf.io/) or the other [community channels](https://prometheus.io/community/).

## Steps to Contribute

Should you wish to work on an issue, please claim it first by commenting on the GitHub issue that you want to work on it.
This is to prevent duplicated efforts from contributors on the same issue.

Please check the [`good first issue`](https://github.com/prometheus/blackbox_exporter/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) and [`help wanted`](https://github.com/prometheus/blackbox_exporter/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) labels to find issues that are good for getting started. If you have questions about one of the issues, please comment on it and one of the maintainers will clarify it.

Before you start, search open and closed issues and PRs for the same change. If a PR exists, build on it.
Duplicate, inactive or superseded PRs are closed in favour of the one closest to master.
Ideas a maintainer declined are not reopened without new information or use cases.

Bug reports need the filled-in issue template, reproduced on a current official release.
Network, target and config problems are not exporter bugs until a reproduction shows otherwise.
Issues with the Helm chart, operator or Alertmanager should go to those repos.

For complete instructions on how to compile see: [Building the software](README.md#building-the-software)

Before you open a PR, run these checks locally and make sure they pass:

```bash
make style check_license unused build test
make lint
make yamllint
./blackbox_exporter --config.file=example.yml --config.check
./blackbox_exporter --config.file=blackbox.yml --config.check
git diff --exit-code
```

If `make lint` reports an issue and you think it is a false positive, you can add a `//nolint:linter1[,linter2,...]` comment before the offending line. Use this sparingly, fixing the code is the preferred course of action.

## Pull Request Checklist

* Branch from the master branch and, if needed, rebase to the current master branch before submitting your pull request. If it doesn't merge cleanly with master you may be asked to rebase your changes.

* Commits should be as small as possible, while ensuring that each commit is correct independently (i.e., each commit should compile and pass tests).

* One concern per PR. No drive-by refactors, renames, reformatting or lint fixes without agreement from a maintainer.

* Fill in the PR template: a title in the form `area: short description`, a short factual description with `Fixes #XXX`, and the `release-notes` block. Use `[BUGFIX]` only if something was broken and `[CHANGE]` for anything existing users can notice. Maintainers write the changelog at release time.

* Every claim in the description must be verified. "Existing users are unaffected" means you tested it.

* Address every review comment with a code change or a reply, and do not resolve comments you did not address. If you cannot finish the requested changes, say so or close the PR so others can pick it up.

* If your patch is not getting reviewed, ask in `#prometheus-exporters-dev` on the [CNCF Slack](https://slack.cncf.io/) instead of tagging maintainers.

PRs that duplicate an open or merged PR, repeat a declined change, fail CI, lack DCO sign-off or have no test for the change are closed without review.

## Dependency management

blackbox_exporter uses [Go modules](https://golang.org/cmd/go/#hdr-Modules__module_versions__and_more) to manage dependencies on external packages. Do not add a new dependency without agreement in the issue.

## Design principles and guidelines

* One `/probe` request runs one probe with one attempt against one target. There are no retries, no DNS cache and no state kept between probes, by design. DNS caching is the host resolver's job.
* HTTP probes behave like `curl --resolve`: dial the resolved IP and keep the hostname in the Host header and SNI. When behaviour is unclear, match curl for HTTP and dig for DNS.
* Response checks stay fast and simple. Content analysis, network policy enforcement and protocols that a dedicated exporter already covers are out of scope.
* HTTP client, auth and TLS settings come from `prometheus/common`. New auth schemes or client options go there first.
* TLS follows Go `crypto/tls` defaults. Removed or insecure options are not brought back.
* Use the standard library or existing dependencies, not deprecated or experimental packages. Do not implement protocols or auth by hand, and do not add deprecated or non-standard protocols.
* Existing users must not be broken without notice. New behaviour is opt-in through one short config field, and defaults stay the same.
* Module settings cannot be overridden from `/probe` URL parameters.
* Reject invalid or conflicting config at load time in `UnmarshalYAML` or `Validate`, not at probe time.
* A failed check sets `probe_success` to 0, because users alert on it.
* An option that applies to several probers (TLS, IP protocol and similar) works in all of them.
* Secrets never go in the target URL and are never logged. Use `credentials_file`, `password_file` or header files.
* Metric names start with `probe_` and the prober name where one applies, and follow the [Prometheus naming guide](https://prometheus.io/docs/practices/naming/). Keep help text short.
* No unbounded or high-churn labels such as IP addresses or response content. Put metadata in a separate `_info` metric.
* Failure reasons go in logs and the `/logs` endpoint, not in metrics. Debug output does not dump response bodies.
* Register metrics on the probe's own registry. No package-level mutable state and no metrics on the default registry.
* Prometheus org-wide topics (exposition format, release signing, exporter self-metrics) are not decided in this repo. Files synced by prometheus/prometheus `scripts/sync_repo_files.sh` (for example `Makefile.common` and `.yamllint`) are changed there.

## Code, tests and docs

* Follow the existing style of the file you are editing. Comments explain why, not what.
* Pin GitHub Actions by commit digest and container images by version tag.
* Performance changes need a benchmark. Run `go test -count=6 -benchmem -bench . ./<package>` before and after, and put the `benchstat` output in the PR description.
* Every bugfix and behaviour change needs a test that fails on master and passes with the change. Confirm the bug exists on current master before you fix it.
* Add cases to existing table-driven tests and reuse the helpers in the test file.
* New config fields need a module in `config/testdata/blackbox-good.yml`. New validation rules need a `TestLoadBadConfigs` case with its own testdata file.
* Tests are hermetic and pass with `-race`. Use `httptest` or in-process servers on loopback, with no internet, host DNS or sleeps.
* New or changed config fields go in `CONFIGURATION.md` in the style of the surrounding entries, with defaults, mutual exclusions, limits and caveats. Examples go in `example.yml` and must pass `--config.check`.
* Docs describe what the code does. Do not document behaviour you did not verify.

## AI-assisted contributions

* AI tools are allowed but if you're sending a change, you must fully understand and review the change before opening the PR, and the DCO sign-off certifies that you have right to submit the change. Fully automated PRs will be closed.
* Disclosing AI use with an `Assisted-by: <tool>` commit trailer is encouraged.
* Write the PR description, issue text and review replies yourself.
* Discussion on issues and PRs is between humans, so don't paste LLM responses.
