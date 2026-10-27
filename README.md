# PHP Security Verify

Local red-team regression tests for the [CalCyber PHP security backports](https://github.com/Calcyber-Security/php-security-backports)
for CVE-2026-109618 and CVE-2026-109619. This runner compares matched unpatched and
patched builds in disposable Docker containers.

The recorded 26 October 2026 lab run passed **12/12 runtime assertions** and
**6/6 runner unit tests**. See [the JSON summary](evidence/summary.json) and
[build provenance](BUILD_PROVENANCE.md). This validates the behaviors below on
the tested PHP 7.4.33 and 7.4.33-p1 CLI/CGI builds; it is not a deployed-site
vulnerability scanner or a guarantee for every backport branch.

The runner accepts no URL, creates no listener and publishes no port.

## Tested scope

- Baseline: minimal PHP 7.4.33 amd64 CLI and CGI builds.
- Backport: PHP 7.4.33-p1, CalCyber commit
  `51c83a94789563515a275a3f55dc52ca3cd867fd`.
- Both builds use the same official PHP release archive, base image, compiler,
  build script and configure options. The patched variant additionally applies
  mitigation `16c7f82e9254eb50bf8fbc5412af5a41856db99b` and its version commit.
- Official base image: `sha256:691f9ae2a3639de11d95f507bc29c723a7f27b79bdf91317aef8ded35f9864ce`.

This is a finite regression test of the reviewed legacy mitigation. It does not
prove RCE, complete CVE absence, application compatibility, loaded Apache/FPM
identity, or coverage of other PHP versions/branches. CGI children are separate
processes; persistent worker/request reuse is not covered.

## Assertions

1. PHP control executes the expected CGI build and parses a normal field.
2. Three ordinary fields with a configured multipart limit of two: the baseline
   parses three; the backport parses two and emits its limit warning.
3. One-byte normal upload with a valid test cookie: progress state is created on
   the baseline and absent on the backport even with the INI option enabled.
4. The original tiny invalid-session scenario: the baseline emits the three
   startup warning categories; the backport does not, and still reaches PHP.
5. One disposable CLI child has an 8 MiB PHP memory limit and requests a 64 MiB
   string. The baseline exits 255 after reaching shutdown; the backport exits 1
   without shutdown. A startup marker and actual memory-error message are
   required; arbitrary crashes, timeouts, signals and nonzero exits fail.
6. The final CGI control retains the same version, SAPI, fields and response
   marker. Deliberately created session test state is excluded from this health
   comparison.

`LAB_ASSERTIONS_PASS` on the baseline means the expected *unpatched* behavior
was reproduced. It does not mean that baseline is secure. Only matched outcomes
on both variants produce `DIFFERENTIAL_LAB_PASS`.

## Corrections from the supplied bundle

- PHP 7.4 reports `The session id is too long ...`; the ZIP expected the exact
  case-sensitive text `Session ID is too long ...`. Matching now accommodates the
  actual wording, while still requiring all three warning categories.
- CGI warnings during multipart startup require `display_startup_errors=1` in
  this lab. Quiet output with startup diagnostics disabled is inconclusive.
- A version suffix or operator-supplied attestation does not establish a fix.
  The runner records and checks the copied CLI/CGI artifact hashes and patch
  input hashes for these locally constructed images.
- HTTP response absence or an unrelated child failure cannot produce success.
- The control endpoint works without the optional PHP JSON extension, omitted
  by the matched `--disable-all` builds.

## Run in a prepared local lab

Prerequisites are the existing successfully exited containers
`calcyber-lab-baseline-build-v2` and `calcyber-lab-patched-build`, built with the
included `build-minimal.sh` and pinned patches. A clean machine must prepare
those matched builds first; this package does not download, compile or install
anything automatically. `BUILD_PROVENANCE.md` records the recovered build setup.

From WSL, with Docker available:

```sh
python3 -I -m unittest discover -s regression -p test_run_regressions.py -v
python3 -I regression/run_regressions.py --output /absolute/path/new-results
```

The output directory must not already exist. A failure is retained and not
automatically retried. Stop and investigate host crashes/disconnections.

Before executing children, the runner checks successful builder termination,
base-image identity, patch hashes and binary hashes. It stages files without
starting the staging container, snapshots it, then inspects the actual runtime
limits: nonroot UID 65534, no network or mounts, read-only root, all capabilities
dropped, no-new-privileges, 256 MiB RAM with no additional swap, half a CPU,
32 PIDs, 16 MiB tmpfs and bounded Docker logs. Every PHP child has a ten-second
timeout. Containers are stopped after the suite and never auto-restarted.

The runner retains stopped containers/snapshot images for evidence. Remove only
the exact resources named in its result records when finished; never use a
global prune on a machine with unrelated workloads. Build containers are kept
for reuse. Binary export directories in results are local lab artifacts, not
production packages or an authenticated vendor distribution.

## Evidence and distribution

`summary.json` and each variant's `results.json` include raw fixture responses,
exit codes, binary hashes and runtime-image identities. Share claims at this
scope only. The packaged evidence is a snapshot of the completed local run.

This repository contains an independently written local regression
runner and fixtures; it excludes the original ZIP's remote scanner and large
multipart sweep. The patch files retain their upstream PHP contributor notices
and provenance; PHP source licensing remains authoritative. No new blanket
license is assigned to the source project or original ZIP. See [third-party
notices](THIRD_PARTY.md) for the included PHP and Zend patch material.
