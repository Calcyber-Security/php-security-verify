# PHP Security Verify

> **The backports tested here are for legacy systems that cannot run supported PHP—including applications that cannot be upgraded at all.** Upgrade to supported, patched PHP whenever feasible. Backports provide targeted risk reduction where an application must remain on legacy PHP, whether the upgrade is delayed or impossible for that application.
>
> A backport covers documented issues only; it does not restore upstream support or provide comprehensive security coverage. Continued legacy operation requires ongoing maintenance, isolation, monitoring and security review. Prefer a fixed, maintained operating-system or LTS vendor package where available. Where upgrading is impossible, consider application replacement or system retirement as the longer-term path. This is not a promise of indefinite security or future patch coverage. See [PHP's current support policy](https://www.php.net/supported-versions.php).

Active single-site PHP2Shell regression checks and local backport validation for
CVE-2026-109618 and CVE-2026-109619. The patches under test are in
[CalCyber PHP Security Backports](https://github.com/Calcyber-Security/php-security-backports).

## Download and run against your own PHP site

Download [verify.py](https://raw.githubusercontent.com/Calcyber-Security/php-security-verify/main/verify.py).
It needs Python 3.10+ and its standard library. No Docker, PHP installation on
your laptop, dependencies or local lab are required for this command:

```sh
python3 verify.py https://your-site.example/index.php --acknowledge-impact --output site-result.json
```

Windows: use `py -3` in place of `python3`.

**This is an intrusive active test.** Use a PHP route you are authorized to test,
not a real upload, payment or business-action handler. It sends a small upload
and a public 1 MiB multipart/OOM regression request. It can terminate PHP
workers, disrupt production requests, or trigger application upload side
effects. The acknowledgment flag is required before any request is sent.

The command uses active response evidence; PHP version headers do not decide
the result. It does not execute a remote system command. If you require command
execution as proof, this client does not provide that proof. See the
[review of the supplied RCE PoC](POC_REVIEW.md).

**CalCyber Apache comparison:** matched PHP 7.4.33 and CalCyber 7.4.33-p1 builds
passed 12/12 runtime assertions. The same producer/cleanup sequence corrupted
the unpatched worker's heap; the backport exited the worker before stale state
could be consumed. See [the validation and its scope](APACHE_VALIDATION.md).
Full command execution on PHP 7.4 was not established.

Default: at most six serial requests to that exact URL, normal controls before
and health checks after probes, one 1 MiB parser probe, TLS certificate
verification, 256 KiB response capture, no redirects, discovery, concurrency or
retries. It stops on filtering, rate limiting, health problems or decisive
behavior. Response bodies, authentication headers, URL paths and query strings
are excluded from the JSON report.

- `--session-only` sends at most four requests and omits the OOM/parser probe.
  This still exercises session startup and is not impact-free.
- `--extended` permits the public 8 MiB and 20 MiB probes if earlier results show
  no decisive behavior: at most ten requests and about 29 MiB of parser inputs.
- `--headers-file private-headers.json` loads any required authentication
  headers from a local JSON object. It is not included in reports. The session
  probe replaces `PHPSESSID` with its test value, so PHP-session-authenticated
  routes may return a login boundary and must remain inconclusive.
- `--timeout 10` controls the per-operation/body budget. Choose a fresh output
  filename; existing reports are not overwritten.

### Reading the result

| Result | What was actually observed |
| --- | --- |
| `LEGACY_SESSION_BEHAVIOR_OBSERVED` | The probe exposed all three legacy session warning categories absent from controls. It does not establish cross-request exploitation. |
| `VULNERABLE_OOM_PATH_OBSERVED` | The multipart request produced the legacy startup OOM/Unknown signature. RCE is not demonstrated. |
| `WORKER_FAILURE_SUSPECTED` | Empty/error response or a transport failure: investigate logs; patched workers can also terminate on hard OOM. |
| `HEALTH_CHECK_FAILED` | The route was unhealthy after the probe. Stop testing and investigate. |
| `MITIGATION_BEHAVIOR_OBSERVED` | The runtime's multipart part limit actively fired. This is positive mitigation evidence, not complete patch verification. |
| `NO_VULNERABLE_BEHAVIOR_OBSERVED` | No tested signature appeared. Hidden errors, proxies, configurations and untested paths prevent a patched verdict. |
| `INCONCLUSIVE` / `RATE_LIMITED` | No usable runtime conclusion; testing stopped. |

Exit codes: `10` means legacy session/OOM behavior, `11` means a suspected worker
failure or failed health check, `20` means mitigation evidence/no signature/
inconclusive, and `2` means invalid CLI input. **No exit code means the site is
secure.** Reports always keep `rce_proven=false` and `patch_verified=false`.

The active HTTP client was validated against the exact unpatched/backported
PHP 7.4 CGI builds through a loopback HTTP adapter. It distinguished the legacy
session and startup OOM paths from the patched multipart limit. Evidence is in
[active-http.json](evidence/active-http.json). That initial run used HTTP/CGI;
the subsequent [Apache comparison](APACHE_VALIDATION.md) covers a controlled
persistent mod_php worker. FPM and production deployments remain unvalidated.

## Local developer regression lab

The original developer runner compares matched unpatched and patched builds in
disposable Docker containers. It is separate from the URL-based command above.

The recorded 26 October 2026 lab run passed **12/12 runtime assertions** and
**6/6 runner unit tests**. See [the JSON summary](evidence/summary.json) and
[build provenance](BUILD_PROVENANCE.md). This validates the behaviors below on
the tested PHP 7.4.33 and 7.4.33-p1 CLI/CGI builds; it is not a deployed-site
vulnerability scanner or a guarantee for every backport branch.

The developer runner accepts no URL, creates no listener and publishes no port.

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
processes; the original CLI/CGI suite does not cover persistent worker reuse.
The later [Apache validation](APACHE_VALIDATION.md) adds that specific coverage.

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
