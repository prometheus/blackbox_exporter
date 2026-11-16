# End-to-end tests

These tests run the exporter's Docker image against a test server, testserver, in Docker Compose.

## Run

```bash
make test-e2e
```

You need Docker with Compose v2 or later and buildx 0.17 or later.
The run builds the exporter into `.build/linux-<arch>/`, which Git ignores.
It overwrites your own build for that architecture.

Run one test:

```bash
go test -tags e2e -count=1 -run '^TestICMP$/^ipv6_as_nobody$' ./e2e/
```

Set `E2E_KEEP=1` to keep the containers after the run.
The run then prints the command that removes them.

## Unit test or e2e test

Write a unit test in `prober/` or `config/` by default.
Write an e2e test only when the test needs:

* the image: its default command, the baked-in config, running as a non-root user,
* exporter flags and endpoints: web config, route prefix, `/-/reload`, SIGHUP, auto reload, `/logs`,
* ICMP sockets: unprivileged sockets, the fallback to raw sockets, `dont_fragment`,
* container networking: Docker's DNS, IPv6 and the fallback between IP protocols.

## Add a test

* For a probe, add a row to the cases in the prober's test, for example `TestICMP` in `icmp_test.go`.
  A new prober gets its own file with a `Test<Prober>` that builds its cases and calls `runCases`.
  If a case expects `probe_success 0`, set `wantLog` to the log line that proves why it failed.
* For a flag or an endpoint, add a test to `exporter_test.go` that starts its own exporter with `startExporter`.
* If testserver needs a new port or record, add it in `testserver/`.
* Add the test for a bug in the same PR as the fix.

Run `make test-e2e`.
Then break the feature in the exporter and run it again.
The new test must fail.
