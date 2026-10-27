#!/usr/bin/env python3
"""Compare two pinned, locally built PHP variants inside offline Docker sandboxes.

No URL/host option, listener, published port, host mount, or remote scanner.
PASS means these finite lab assertions passed, never a serving/fleet verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE_IMAGE = 'sha256:691f9ae2a3639de11d95f507bc29c723a7f27b79bdf91317aef8ded35f9864ce'
BUILDERS = {
    'baseline': ('calcyber-lab-baseline-build-v2', '7.4.33'),
    'patched': ('calcyber-lab-patched-build', '7.4.33-p1'),
}
PATCHES = {
    'mitigation.patch': 'ad8e568b543ee2d29a07d5df5cf7336616ebf145d156d9c8d4d4f0c1d9a90b1b',
    'version.patch': 'c9f4a7e7607a31f5f2043b8e6a7aa926655ca002be81580df2462cfe5a015324',
}


def command(argv, *, data=None, timeout=30, check=True):
    proc = subprocess.run(argv, input=data, capture_output=True, timeout=timeout, check=False)
    result = {
        'exit_code': proc.returncode,
        'stdout': proc.stdout.decode('utf-8', 'replace')[-65536:],
        'stderr': proc.stderr.decode('utf-8', 'replace')[-65536:],
    }
    if check and proc.returncode:
        raise RuntimeError(f'{argv[:3]} failed: {result}')
    return result


def docker(*args, **kwargs):
    return command(['docker', *map(str, args)], **kwargs)


def inspect(name):
    return json.loads(docker('inspect', name)['stdout'])[0]


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            digest.update(block)
    return digest.hexdigest()


def validate_runtime(spec):
    host = spec['HostConfig']
    assert host['NetworkMode'] == 'none'
    assert host['ReadonlyRootfs'] is True
    assert host['Memory'] == 256 * 1024 * 1024
    assert host['MemorySwap'] == host['Memory']
    assert host['NanoCpus'] == 500000000
    assert host['PidsLimit'] == 32
    assert spec['Config']['User'] == '65534:65534'
    assert host['RestartPolicy']['Name'] == 'no'
    assert 'no-new-privileges:true' in host['SecurityOpt']
    assert host['CapDrop'] == ['ALL']
    assert not spec.get('Mounts')
    assert not host.get('PortBindings')
    assert host['LogConfig']['Type'] == 'local'
    assert host['LogConfig']['Config']['max-size'] == '1m'
    assert set(host['Tmpfs']) == {'/tmp'}
    assert 'size=16777216' in host['Tmpfs']['/tmp']


def multipart(fields, *, upload=False):
    boundary = 'calcyber-finite-regression'
    parts = []
    for name, value in fields:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    if upload:
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="fixture"; filename="fixture.txt"\r\nContent-Type: text/plain\r\n\r\n1\r\n'.encode())
    parts.append(f'--{boundary}--\r\n'.encode())
    body = b''.join(parts)
    assert len(body) < 2048
    return body, boundary


def endpoint_json(result):
    if result['exit_code'] != 0:
        return None
    lines = dict(line.split('=', 1) for line in result['stdout'].splitlines()
                 if line.startswith('CALCYBER_LAB_') and '=' in line)
    required = ['MARKER', 'VERSION', 'SAPI', 'FILE_COUNT', 'MULTIPART_LIMIT']
    if any('CALCYBER_LAB_' + key not in lines for key in required):
        return None
    if lines['CALCYBER_LAB_MARKER'] != 'CALCYBER_ISOLATED_LAB_CONTROL':
        return None
    try:
        return {'marker': lines['CALCYBER_LAB_MARKER'],
                'version': lines['CALCYBER_LAB_VERSION'], 'sapi': lines['CALCYBER_LAB_SAPI'],
                'file_count': int(lines['CALCYBER_LAB_FILE_COUNT']),
                'multipart_limit': lines['CALCYBER_LAB_MULTIPART_LIMIT'],
                'cookie': lines.get('CALCYBER_LAB_COOKIE'),
                'progress_enabled': lines.get('CALCYBER_LAB_PROGRESS'),
                'session_progress_file': lines.get('CALCYBER_LAB_SESSION_PROGRESS_FILE'),
                'fields': {key[len('CALCYBER_LAB_FIELD_'):]: value for key, value in lines.items()
                           if key.startswith('CALCYBER_LAB_FIELD_')}}
    except ValueError:
        return None


def oom_matches(result, variant):
    output = result['stdout'] + result['stderr']
    reached = 'CALCYBER_OOM_STARTED' in output
    exhausted = bool(re.search(r'Allowed memory size of .* bytes exhausted', output))
    shutdown = 'CALCYBER_SHUTDOWN_REACHED' in output
    expected_exit = 255 if variant == 'baseline' else 1
    return (result['exit_code'] == expected_exit and reached and exhausted
            and 'CALCYBER_OOM_NOT_REACHED' not in output
            and shutdown == (variant == 'baseline'))


def control_matches(actual, expected):
    # Session progress is deliberate test state, not application-health identity.
    keys = ('marker', 'version', 'sapi', 'fields', 'file_count', 'multipart_limit')
    return bool(actual and expected and all(actual.get(key) == expected.get(key) for key in keys))


def session_warning_markers(output):
    # PHP 7.4 says "The session id ..."; newer messages use "Session ID ...".
    folded = output.casefold()
    return [marker in folded for marker in
            ('session id is too long or contains illegal characters',
             'failed to read session data', 'failed to write session data (')]


def cgi(container, fields=(), *, upload=False, cookie=False, limit=10):
    body, boundary = multipart(fields, upload=upload)
    env = {
        'REDIRECT_STATUS': '1', 'REQUEST_METHOD': 'POST',
        'SCRIPT_FILENAME': '/input/endpoint.php', 'SCRIPT_NAME': '/endpoint.php',
        'CONTENT_TYPE': f'multipart/form-data; boundary={boundary}',
        'CONTENT_LENGTH': str(len(body)), 'SERVER_PROTOCOL': 'HTTP/1.1',
    }
    if cookie:
        env['HTTP_COOKIE'] = 'PHPSESSID=' + ('calcyberfixture' if cookie is True else cookie)
    argv = ['exec', '-i']
    for key, value in env.items():
        argv += ['-e', f'{key}={value}']
    argv += [container, 'timeout', '10', '/opt/lab-php/bin/php-cgi', '-n']
    for setting in ['memory_limit=32M', 'post_max_size=1M', 'display_errors=1',
                    'display_startup_errors=1', 'error_reporting=32767',
                    'html_errors=0', 'log_errors=0', 'session.save_path=/tmp',
                    'session.upload_progress.enabled=1', 'session.upload_progress.cleanup=0',
                    f'max_multipart_body_parts={limit}']:
        argv += ['-d', setting]
    return docker(*argv, data=body, timeout=20, check=False)


def run_variant(variant, output):
    builder, version = BUILDERS[variant]
    source = inspect(builder)
    assert source['Image'] == BASE_IMAGE
    assert source['State']['Status'] == 'exited'
    assert source['State']['ExitCode'] == 0 and not source['State']['OOMKilled']
    assert source['HostConfig']['NetworkMode'] == 'none'
    assert source['HostConfig']['Memory'] == 2 * 1024**3
    assert not source.get('Mounts')
    destination = output / variant
    destination.mkdir()
    docker('cp', f'{builder}:/opt/lab-php', destination / 'lab-php')
    docker('cp', f'{builder}:/input/build-minimal.sh', destination / 'build-minimal.sh')
    hashes = {name: sha256(destination / 'lab-php' / 'bin' / name) for name in ('php', 'php-cgi')}
    build_log = docker('logs', '--tail', '12', builder)
    for name, digest in hashes.items():
        assert f'{digest}  /opt/lab-php/bin/{name}' in build_log['stdout'] + build_log['stderr']
    if variant == 'patched':
        for name, expected in PATCHES.items():
            docker('cp', f'{builder}:/input/{name}', destination / name)
            assert sha256(destination / name) == expected
    container = f'calcyber-php-regression-{variant}-{output.name}'
    # Docker cannot copy into even a stopped read-only container. Stage files
    # without starting a process, snapshot, then enforce read-only at runtime.
    staging = container + '-stage'
    docker('create', '--name', staging, '--network', 'none', '--entrypoint', '/bin/true', BASE_IMAGE)
    docker('cp', destination / 'lab-php', f'{staging}:/opt/lab-php')
    docker('cp', HERE, f'{staging}:/input')
    image = docker('commit', staging)['stdout'].strip()
    docker('create', '--name', container, '--network', 'none', '--read-only',
           '--user', '65534:65534', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
           '--memory', '256m', '--memory-swap', '256m', '--cpus', '0.5', '--pids-limit', '32',
           '--restart', 'no', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777',
           '--log-driver', 'local', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1',
           '--log-opt', 'compress=false', '--entrypoint', '/bin/sh', image, '-c', 'exec sleep 600')
    runtime = inspect(container)
    validate_runtime(runtime)
    evidence = {'variant': variant, 'builder': builder, 'container': container,
                'expected_version': version, 'binary_sha256': hashes, 'checks': {},
                'builder_source_image': BASE_IMAGE, 'runtime_image': image,
                'build_script_sha256': sha256(destination / 'build-minimal.sh'),
                'isolation': {key: runtime['HostConfig'][key] for key in
                              ('NetworkMode', 'Memory', 'MemorySwap', 'NanoCpus', 'PidsLimit', 'ReadonlyRootfs')},
                'scope': 'Locally compiled CLI/CGI fixtures only; no deployed service or exploitability claim.'}
    # Checkpoint before any child starts. A failed run is retained and never auto-retried.
    (destination / 'started.json').write_text(json.dumps(evidence, indent=2) + '\n')
    try:
        docker('start', container)
        actual_hashes = docker('exec', container, 'sha256sum', '/opt/lab-php/bin/php', '/opt/lab-php/bin/php-cgi')
        assert all(value in actual_hashes['stdout'] for value in hashes.values())
        control = cgi(container, [('control', '1')])
        control_json = endpoint_json(control)
        control_ok = bool(control_json and control_json['version'] == version
                          and control_json['fields'] == {'control': '1'} and control_json['sapi'] == 'cgi-fcgi')
        evidence['checks']['pre_control'] = {'passed': control_ok, 'response': control}
        if not control_ok:
            raise RuntimeError('CGI control failed; no regression children launched')
        bounded = cgi(container, [('one', '1'), ('two', '2'), ('three', '3')], limit=2)
        parsed = endpoint_json(bounded)
        expected_fields = {'one': '1', 'two': '2'}
        if variant == 'baseline':
            expected_fields['three'] = '3'
        limit_warning = 'Multipart body parts limit exceeded' in bounded['stdout'] + bounded['stderr']
        evidence['checks']['multipart_limit'] = {
            'passed': bool(parsed and parsed['fields'] == expected_fields and limit_warning == (variant == 'patched')),
            'response': bounded,
        }
        session = cgi(container, [('PHP_SESSION_UPLOAD_PROGRESS', 'fixture')], upload=True, cookie=True)
        session_json = endpoint_json(session)
        session_output = session['stdout'] + session['stderr']
        markers = session_warning_markers(session_output)
        evidence['checks']['session_lifecycle'] = {
            'passed': bool(session_json and session_json['file_count'] == 1
                           and session_json['cookie'] == 'calcyberfixture'
                           and session_json['progress_enabled'] == '1'
                           and session_json['session_progress_file'] == ('PRESENT' if variant == 'baseline' else 'ABSENT')),
            'assertion': 'valid one-byte upload creates session progress only before mitigation; no invalid-session exploitability claim',
            'warning_markers': markers, 'response': session,
        }
        invalid = cgi(container, [('PHP_SESSION_UPLOAD_PROGRESS', 'fixture')], upload=True, cookie='_')
        invalid_json = endpoint_json(invalid)
        invalid_output = invalid['stdout'] + invalid['stderr']
        invalid_markers = session_warning_markers(invalid_output)
        evidence['checks']['invalid_session_startup'] = {
            'passed': bool(invalid_json and invalid_json['file_count'] == 1
                           and (all(invalid_markers) if variant == 'baseline' else not any(invalid_markers))),
            'warning_markers': invalid_markers, 'response': invalid,
        }
        oom = docker('exec', container, 'timeout', '10', '/opt/lab-php/bin/php', '-n',
                     '-d', 'memory_limit=8M', '-d', 'display_errors=1', '-d', 'log_errors=0',
                     '/input/oom.php', timeout=20, check=False)
        evidence['checks']['oom_lifecycle'] = {'passed': oom_matches(oom, variant), 'response': oom}
        post = cgi(container, [('control', '1')])
        evidence['checks']['post_control'] = {'passed': control_matches(endpoint_json(post), control_json), 'response': post}
    finally:
        docker('stop', '--time', '2', container, check=False)
        state = inspect(container)['State']
        evidence['container_oom_killed'] = state['OOMKilled']
        evidence['status'] = ('LAB_ASSERTIONS_PASS' if len(evidence['checks']) == 6
                              and all(item['passed'] for item in evidence['checks'].values())
                              and not state['OOMKilled'] else 'LAB_ASSERTIONS_FAILED')
        (destination / 'results.json').write_text(json.dumps(evidence, indent=2) + '\n')
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(exist_ok=False, parents=True)
    results = []
    for variant in BUILDERS:
        result = run_variant(variant, output)
        results.append(result)
        print(json.dumps({'variant': variant, 'status': result['status'],
                          'checks': {name: item['passed'] for name, item in result['checks'].items()}}), flush=True)
    same_build_script = len(results) == 2 and results[0]['build_script_sha256'] == results[1]['build_script_sha256']
    summary = {'generated_utc': datetime.now(timezone.utc).isoformat(),
               'backport_commit': '51c83a94789563515a275a3f55dc52ca3cd867fd',
               'same_build_script': same_build_script,
               'status': 'DIFFERENTIAL_LAB_PASS' if same_build_script and all(
                   item['status'] == 'LAB_ASSERTIONS_PASS' for item in results) else 'INCOMPLETE_OR_FAILED',
               'limitations': ['PHP 7.4.33 amd64 minimal CLI/CGI only.',
                               'No Apache/FPM persistence, production serving identity or fleet validation.',
                               'Finite mitigation regression checks, not proof of CVE absence or RCE.'],
               'results': results}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(summary['status'])
    return 0 if summary['status'] == 'DIFFERENTIAL_LAB_PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
