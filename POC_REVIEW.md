# Supplied command-execution PoC: review and controlled validation

Reviewed source: [eness/php2shell PoC](https://github.com/eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC/tree/df8b16fe69ab7218f496b5d88127253fc90ff92e),
commit `df8b16fe69ab7218f496b5d88127253fc90ff92e`. The initial static review was
followed by controlled local Apache tests on 26 October 2026 PDT. The PoC is
not vendored. Tested source SHA256:
`ac58c5ab5a487af59a26625e458af9b115b1e7041b190e048d9b4c9ef2109378`.

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

## Observed PHP 7.4 behavior

On an official unpatched PHP 7.4.33 Apache image, one bounded attempt with each
supplied profile failed at the heap-leak stage and produced worker SIGSEGVs.
Neither fresh proof path appeared. Function offsets were derived from the
actual PHP 7.4 module; this did not supply a compatible allocator profile.

We then rebuilt matched minimal PHP 7.4.33 and CalCyber 7.4.33-p1 Apache modules
from the same release archive and identical configuration. The PoC's rotation
sequence provided a corruption control: its OOM producer left the baseline
worker alive, and its cleanup request reached that same worker and produced
`zend_mm_heap corrupted`. With the CalCyber module, the producer terminated the
worker before the cleanup request, which completed in a fresh worker without
heap corruption. Independent upload-progress, multipart-limit, OOM shutdown and
ordinary-request checks also matched the intended mitigation.

The final comparison passed 12/12 assertions. Both full RCE attempts still
failed at the heap-leak stage; no fresh command-execution proof was produced.
This confirms the tested mitigation behavior and interruption of the reproduced
corruption chain, while full RCE patch verification remains unestablished.
See [Apache validation](APACHE_VALIDATION.md) and
[recorded evidence](evidence/apache-mitigation.json).

Authoritative scope: [PHP OOM advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [PHP stale-state advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).
