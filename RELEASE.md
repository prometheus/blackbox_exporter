# Releases

This page describes how blackbox_exporter releases are cut.

There is no fixed schedule for the release, maintainers cut a release when master has enough user-facing changes or a fix that users need.

## How to cut a release

### 1. Prepare the release

We aim to keep master in a working state at all times, so releases are cut from master.

Before the release, check the state of master:
- Expedite bug fixes that should make it into the release, and hold back changes that are better suited for the next release.
- Update dependencies, so the release ships with current versions.
- Run `govulncheck ./...` with the Go version CI uses and fix everything it reports before the release PR, so the release ships with no known vulnerabilities.
- Bump the version in the `VERSION` file and add a new `<version> / <date>` section to `CHANGELOG.md`.
- Collect the entries from the `release-notes` blocks of the PRs merged since the last release.
- `CHANGELOG.md` should only document changes relevant to users of blackbox_exporter.
- Open a PR titled `Release vX.Y.Z` against master with only the `VERSION` and `CHANGELOG.md` changes, for example [#1692](https://github.com/prometheus/blackbox_exporter/pull/1692).
- Wait for CI and an approval, then merge it.

### 2. Tag the release

Tag the merged release commit on master:

```bash
tag="v$(< VERSION)"
git tag -s "${tag}" -m "${tag}"
git push upstream "${tag}"
```

NOTE: `upstream` is the remote for `prometheus/blackbox_exporter`.

Release tags must be signed.
To sign with an SSH key, [tell git about your SSH key](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key#telling-git-about-your-ssh-key) and [add it to your GitHub account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account) as a signing key. See GitHub's [signing tags](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-tags) guide for more.

### 3. Publish the release

Pushing a `v*` tag runs the `publish_release` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml), and uploads the tarballs to the GitHub release and pushes the images to container registries.

Wait for that job to finish, check the drafted GitHub release, then click _Publish release_.

For a release candidate (a `-rc.N` suffix on the version), make sure _This is a pre-release_ is checked.
