# Supplied command-execution PoC: static review

Reviewed source: [eness/php2shell PoC](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC/tree/df8b16fe69ab7218f496b5d88127253fc90ff92e),
commit `df8b16fe69ab7218f496b5d88127253fc90ff92e`. This was a static review;
the PoC was not executed or vendored.

Its Python source implements an RCE attempt using worker aborts, heap/library
address disclosures and build-specific forged runtime structures. Its profiles
target PHP 8.4.26 / Apache prefork configurations, with specific memory/session
settings and binary/heap offsets. That does not establish compatibility with the
CalCyber PHP 7.4.33-p1 build, other EOL builds, FPM or multi-worker production.

The default proof path is local and the command can write a proof file. Its
HTTP proof accepts any nonempty fetched content without a fresh nonce, so stale
content or an application error page could be mistaken for command execution.
The documented automatic-offset helper is absent from the reviewed tree.
No license file was present; its code is not redistributed here.

A trustworthy RCE verification mode needs a compatible build profile, an
independently validated positive control, fresh execution-specific proof,
explicit artifact accounting and reliable failure classification. Failed
exploitation cannot establish a patch. `verify.py` remains an active regression
and crash detector; it does not advertise RCE verification.

Authoritative scope: [PHP OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [PHP stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
