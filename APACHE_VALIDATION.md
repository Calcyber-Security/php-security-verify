# CalCyber PHP 7.4 Apache mitigation validation

On 26 October 2026 PDT, a matched local comparison passed **12/12 runtime
assertions** against PHP 7.4.33 and CalCyber PHP 7.4.33-p1 under Apache prefork.
The tested backport interrupts the reproduced cross-request corruption chain.
This does not establish a complete command-execution exploit on PHP 7.4 or
certify a production deployment.

| Test | Unpatched PHP 7.4.33 | CalCyber PHP 7.4.33-p1 |
| --- | --- | --- |
| Ordinary multipart request | Parses normally; worker reused | Parses normally; worker reused |
| Three fields, part limit set to two | Parses all three | Parses two; emits limit warning |
| Valid upload with progress option enabled | Creates progress session state | Does not create progress state |
| Application OOM with shutdown callback | Runs callback and reuses worker | Exits before callback; replacement serves health check |
| Supplied PoC producer followed by cleanup | Cleanup reaches same worker and reports `zend_mm_heap corrupted` | Producer exits worker; cleanup succeeds in fresh worker without corruption |
| Final PHP health check | Correct version and SAPI | Correct version and SAPI |

The corruption test uses the supplied PoC's `rotate()` request pair. Its producer
and cleanup requests reached baseline worker 12; after the cleanup failure a
health request reached replacement worker 37. With the patch, the producer
exited worker 12; cleanup and health reached worker 31. These are container PIDs.
The patched producer still encounters hard OOM and terminates. The mitigation
prevents reuse of the unsafe state; it does not make oversized requests harmless.

An earlier run used `stage1()` as a crash control. It did not corrupt the matched
baseline and correctly failed overall. The final run isolates the rotation pair
that demonstrably triggered corruption during the full PoC. Both variants
receive identical inputs. A failed baseline control cannot establish mitigation.

## Source and build identity

- CalCyber source: `51c83a94789563515a275a3f55dc52ca3cd867fd`.
- Mitigation: `16c7f82e9254eb50bf8fbc5412af5a41856db99b`, followed by its version-only change.
- PHP archive SHA256: `924846abf93bc613815c55dd3f5809377813ac62a9ec4eb3778675b82a27b927`.
- Official base: `php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d`.
- Both `config.nice` files: `204422555da5c3a0d7d5b52a5b344765d0f14d15da0152ea950d08b88e5c06c1`.
- Baseline module: `a9d5c774e9e883c67bea951d936986a19c75a8a4a8171931d5bfe8e2e98e7fdd`.
- Patched module: `68c78e74f27d3fda9b67d3af7da135e326241a4aaf3510183bc03e19ac6fd2ac`.

Both used `--disable-all --enable-cli --enable-session --without-pear
--with-apxs2=/usr/bin/apxs --prefix=/opt/lab-php`. The patches and version change
are the only PHP source differences. These are minimal test modules, not
production packages. Both used the same compiler image with dependencies from
Debian's signed Bullseye archive; former security package URLs returned 404.

Builds ran sequentially and offline with one CPU, 2 GiB memory, no extra swap,
64 PIDs and a 30-minute deadline. Each finished in about three minutes without
a cgroup OOM kill. Runtime containers used one persistent Apache worker,
8 MiB PHP memory limit, 256 MiB container memory, half a CPU, a read-only root,
nonroot UID, dropped capabilities, no host mounts or published ports, and an
internal network without external routing. All test runtimes stopped afterward.

## Full PoC result and limits

The pinned [supplied PoC](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC/tree/df8b16fe69ab7218f496b5d88127253fc90ff92e)
also ran against both matched modules with their actual function offsets and
the supplied `bookworm` heap profile. Both failed at the heap-leak stage. Each
attempt required an exact fresh nonce at a previously absent proof path;
neither produced proof. The report retains
`rce_positive_control_established=false` and `rce_patch_verified=false`.

The positive control here is explicit cross-request heap corruption, followed
by interruption of that same chain with the patch. Scope is the tested PHP 7.4
build, configuration and inputs. Other branches, FPM, application-specific
state producers and customer installations require their own evidence. See
PHP's [OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
for the broader vulnerability conditions.

## Evidence and developer reproduction

[apache-mitigation.json](evidence/apache-mitigation.json) includes HTTP responses,
worker observations, logs and outcomes.
[apache-builds.json](evidence/apache-builds.json) records the builders.

Reproduction requires Linux/WSL, Docker, Python 3 and `nm`. From this repository
root, on a machine without the exact named test resources:

```sh
curl -fL https://raw.githubusercontent.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC/df8b16fe69ab7218f496b5d88127253fc90ff92e/poc_109618.py -o regression/apache/poc_109618.py
python3 -I regression/apache/prepare_apache_build.py
docker wait calcyber-apache74-dev-20261026-v1
python3 -I regression/apache/build_pair.py
python3 -I regression/apache/validate_apache_pair.py
```

The builder checks setup exited successfully. The validator checks the reviewed
PoC SHA256 before importing it. That external source is ignored by Git and not
redistributed here. The validator only targets containers it creates and has
no remote URL option. Existing output directories or container names cause a
failure rather than overwriting evidence. Keep resulting JSON and logs. Remove
only named test resources when finished; do not prune unrelated workloads.
Customer URL checking still uses root `verify.py` with its existing limitations.
