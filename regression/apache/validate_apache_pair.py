"""Finite matched Apache lifecycle validation; failed RCE never means patched."""
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NETWORK = 'calcyber-rce-isolated-20261026'
SOURCE_HASH = 'ac58c5ab5a487af59a26625e458af9b115b1e7041b190e048d9b4c9ef2109378'
RUN_ID = 'v2'
sys.path.insert(0, str(ROOT))
from elf_handlers import handlers


def run(args, timeout=60, check=True):
    proc = subprocess.run(list(map(str, args)), capture_output=True, timeout=timeout)
    if check and proc.returncode:
        raise RuntimeError(proc.stderr.decode(errors='replace')[-2000:])
    return proc


def docker(*args, **kwargs):
    return run(['docker', *args], **kwargs).stdout.decode()


def spec(name):
    return json.loads(docker('inspect', name))[0]


def logs(name):
    proc = run(['docker', 'logs', '--tail', '300', name])
    return (proc.stdout + proc.stderr).decode(errors='replace')


def workers(name):
    return docker('exec', name, 'cat', '/proc/1/task/1/children').split()


def corruption_chain_matches(case, variant):
    """Require the observed worker transition as well as explicit corruption."""
    observations = case['observations']
    if len(observations) != 2:
        return False
    producer, consumer = observations
    original = producer['worker_before']
    if len(original) != 1:
        return False
    corruption = case['segmentation_faults'] > 0 or case['heap_corruptions'] > 0
    if variant == 'baseline':
        return (corruption and producer['worker_after'] == original
                and consumer['worker_before'] == original
                and consumer['worker_after'] != original)
    return (not corruption and 'Allowed memory size of' in case['log']
            and producer['worker_after'] != original
            and bool(consumer['worker_after'])
            and not set(original).intersection(consumer['worker_after'])
            and consumer['response_status'].startswith('HTTP/1.1 200'))


def request(address, path='/index.php', body=None, headers=None):
    conn = http.client.HTTPConnection(address, 8080, timeout=10)
    status, data, error = 0, b'', ''
    try:
        conn.request('POST' if body is not None else 'GET', path,
                     body=body, headers=headers or {})
        response = conn.getresponse()
        status = response.status
        try:
            data = response.read(256 * 1024)
        except http.client.IncompleteRead as exc:
            data = exc.partial
            error = 'IncompleteRead'
    except (OSError, http.client.HTTPException) as exc:
        error = type(exc).__name__
    finally:
        conn.close()
    text = data.decode(errors='replace')
    values = dict(line.split('=', 1) for line in text.splitlines() if re.match(r'^[A-Za-z_]+=', line))
    return {'status': status, 'body': text, 'error': error, 'values': values}


def health(address, version):
    result = request(address)
    assert result['status'] == 200 and 'CALCYBER_APACHE_CONTROL' in result['body'], result
    assert result['values']['VERSION'] == version and result['values']['SAPI'] == 'apache2handler', result
    return result


def multipart(fields, upload=False):
    boundary = 'calcyber-apache-regression'
    body = bytearray()
    for key, value in fields:
        body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
    if upload:
        body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="fixture"; filename="fixture.txt"\r\nContent-Type: text/plain\r\n\r\n1\r\n'.encode())
    body.extend(f'--{boundary}--\r\n'.encode())
    assert len(body) < 2048
    return bytes(body), {'Content-Type': 'multipart/form-data; boundary=' + boundary}


def fresh(name, version):
    docker('restart', name)
    address = spec(name)['NetworkSettings']['Networks'][NETWORK]['IPAddress']
    assert ipaddress.ip_address(address).is_private
    for _ in range(15):
        time.sleep(.3)
        try:
            return address, health(address, version)
        except AssertionError:
            pass
    raise RuntimeError('Apache control failed after restart')


def prepare(variant, image, fixture):
    name = 'calcyber-apache74-' + variant + '-runtime-20261026-' + RUN_ID
    stage = name + '-stage'
    module = ROOT / ('apache-artifacts-' + variant) / 'libphp7.so'
    docker('create', '--name', stage, '--network', 'none', '--entrypoint', '/bin/true', image)
    docker('cp', str(fixture) + '/.', stage + ':/input')
    docker('cp', module, stage + ':/usr/lib/apache2/modules/libphp7.so')
    snapshot = docker('commit', stage).strip()
    docker('create', '--name', name, '--label', 'org.calcyber.purpose=apache-validation',
           '--network', NETWORK, '--read-only', '--user', '33:33', '--cap-drop', 'ALL',
           '--security-opt', 'no-new-privileges:true', '--memory', '256m',
           '--memory-swap', '256m', '--cpus', '0.5', '--pids-limit', '32', '--restart', 'no',
           '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=33554432,mode=1777',
           '--log-driver', 'local', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1',
           '--log-opt', 'compress=false', '--entrypoint', '/bin/sh', snapshot, '/input/entrypoint.sh')
    state = spec(name)
    host = state['HostConfig']
    assert host['NetworkMode'] == NETWORK and host['ReadonlyRootfs'] and not state['Mounts']
    assert not host['PortBindings'] and host['Memory'] == host['MemorySwap'] == 268435456
    assert host['NanoCpus'] == 500000000 and host['CapDrop'] == ['ALL']
    assert state['Config']['User'] == '33:33' and host['PidsLimit'] == 32
    docker('start', name)
    expected = hashlib.sha256(module.read_bytes()).hexdigest()
    assert docker('exec', name, 'sha256sum', '/usr/lib/apache2/modules/libphp7.so').split()[0] == expected
    return name, expected


def test_variant(variant, image, fixture, poc):
    version = '7.4.33-p1' if variant == 'patched' else '7.4.33'
    name, module_hash = prepare(variant, image, fixture)
    result = {'variant': variant, 'name': name, 'module_sha256': module_hash,
              'checks': {}, 'rce_proven': False, 'rce_patch_verified': False}
    checks = result['checks']
    try:
        address, control = fresh(name, version)
        body, headers = multipart([('alpha', 'A')])
        ordinary = request(address, '/index.php?inspect=1', body, headers)
        checks['ordinary_post'] = {'passed': ordinary['status'] == 200
            and ordinary['values'].get('FIELD_alpha') == 'A'
            and ordinary['values'].get('PID') == control['values']['PID'], 'response': ordinary}

        body, headers = multipart([('alpha', 'A'), ('beta', 'B'), ('gamma', 'C')])
        bounded = request(address, '/limited/index.php?inspect=1', body, headers)
        limited = 'Multipart body parts limit exceeded 2' in bounded['body']
        checks['multipart_limit'] = {'passed': bounded['status'] == 200
            and bounded['values'].get('FIELD_gamma') == ('ABSENT' if variant == 'patched' else 'C')
            and limited == (variant == 'patched'), 'response': bounded}

        body, headers = multipart([('PHP_SESSION_UPLOAD_PROGRESS', 'fixture')], upload=True)
        headers['Cookie'] = 'PHPSESSID=calcyberapachefixture'
        upload = request(address, '/session/index.php?inspect=1', body, headers)
        checks['session_progress_lifecycle'] = {'passed': upload['status'] == 200
            and upload['values'].get('FILE_COUNT') == '1'
            and upload['values'].get('PROGRESS_ENABLED') == '1'
            and upload['values'].get('PROGRESS_FILE') == ('ABSENT' if variant == 'patched' else 'PRESENT'),
            'response': upload}

        address, control = fresh(name, version)
        before_log = logs(name)
        oom = request(address, '/oom.php')
        time.sleep(1.3)
        after_oom = health(address, version)
        marker = run(['docker', 'exec', name, 'test', '-f', '/tmp/calcyber-oom-shutdown'], check=False).returncode == 0
        oom_logs = logs(name)[len(before_log):]
        replaced = control['values']['PID'] != after_oom['values']['PID']
        checks['oom_lifecycle'] = {'passed': 'CALCYBER_OOM_STARTED' in oom['body']
            and 'CALCYBER_OOM_NOT_REACHED' not in oom['body']
            and 'Allowed memory size of' in (oom['body'] + oom_logs)
            and marker == (variant == 'baseline') and replaced == (variant == 'patched'),
            'response': oom, 'shutdown_callback_reached': marker,
            'worker_replaced': replaced, 'log': oom_logs, 'health': after_oom}

        address, control = fresh(name, version)
        observations = []
        baseline_logs = logs(name)

        class ObservedTarget(poc.Target):
            def post(self, body, boundary, **kwargs):
                before = workers(name)
                response = super().post(body, boundary, **kwargs)
                time.sleep(.3)
                after = workers(name)
                observations.append({'request_bytes': len(body), 'worker_before': before,
                    'worker_after': after, 'response_bytes': len(response),
                    'cookie_bytes': len(poc.parse_cookie(response)),
                    'oom_in_response': b'Allowed memory size of' in response,
                    'response_status': response[:32].split(b'\r\n')[0].decode(errors='replace')})
                return response

        target = ObservedTarget(f'http://{address}:8080/index.php', timeout=8, verbose=False)
        exploit = poc.Exploit(target, 'echo ABCD>q12', verbose=False, profile='bookworm')
        exploit.rotate()
        time.sleep(1.3)
        after_pair = health(address, version)
        pair_logs = logs(name)[len(baseline_logs):]
        segfaults = pair_logs.count('exit signal Segmentation fault (11)')
        heap_corruptions = pair_logs.count('zend_mm_heap corrupted')
        checks['exploit_producer_consumer'] = {
            'observations': observations, 'heap_corruptions': heap_corruptions,
            'segmentation_faults': segfaults, 'log': pair_logs, 'health': after_pair,
            'scope': 'Supplied PoC rotation producer/cleanup requests; explicit engine corruption or SIGSEGV required on baseline. This is not command execution.'}
        checks['exploit_producer_consumer']['passed'] = corruption_chain_matches(
            checks['exploit_producer_consumer'], variant)

        address, control = fresh(name, version)
        module = ROOT / ('apache-artifacts-' + variant) / 'libphp7.so'
        zif = handlers(module)['system']
        nm = run(['nm', '-D', '--defined-only', module]).stdout.decode()
        dtor = int(re.search(r'^([0-9a-f]+)\s+\w\s+zval_ptr_dtor$', nm, re.M)[1], 16)
        filename, nonce = 'q' + secrets.token_hex(1), secrets.token_hex(2)
        proof_path = '/' + filename
        assert request(address, proof_path)['status'] == 404
        args = [sys.executable, '-I', ROOT / 'poc_109618.py', '-u',
                f'http://{address}:8080/index.php', '-c', f'echo {nonce}>{filename}',
                '--proof-file', '', '--offsets-file', '', '--no-auto-offsets',
                '--profile', 'bookworm', '--zif-offset', hex(zif), '--dtor-offset', hex(dtor),
                '--retries', '1', '--timeout', '8', '--fetch', proof_path]
        execution = run(args, timeout=180, check=False)
        execution_log = (execution.stdout + execution.stderr).decode(errors='replace')
        (ROOT / ('apache-full-poc-' + variant + '-' + RUN_ID + '.log')).write_text(execution_log)
        proof = request(address, proof_path)
        result['rce_proven'] = proof['status'] == 200 and proof['body'] == nonce + '\n'
        result['full_poc'] = {'exit_code': execution.returncode, 'zif_offset': hex(zif),
            'dtor_offset': hex(dtor), 'heap_leak_failed': 'HEAP_LEAK_FAILED' in execution_log,
            'fresh_nonce_match': result['rce_proven'], 'proof_http_status': proof['status']}
        checks['final_health'] = {'passed': bool(health(address, version))}
        result['passed'] = all(check['passed'] for check in checks.values())
    finally:
        result['apache_log'] = logs(name)
        docker('stop', '--time', '3', name)
        result['container_stopped'] = not spec(name)['State']['Running']
        (ROOT / ('apache-result-' + variant + '-' + RUN_ID + '.json')).write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    source = ROOT / 'poc_109618.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == SOURCE_HASH
    loader = importlib.util.spec_from_file_location('reviewed_local_poc', source)
    poc = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(poc)
    builds = json.loads((ROOT / 'apache-builds.json').read_text())
    assert builds['status'] == 'BOTH_BUILDS_COMPLETE'
    assert json.loads(docker('network', 'inspect', NETWORK))[0]['Internal']
    fixture = ROOT / ('apache-runtime-input-' + RUN_ID)
    fixture.mkdir(exist_ok=False)
    for source_name, destination in [('apache-index.php', 'index.php'), ('apache-oom.php', 'oom.php'),
            ('apache-entrypoint.sh', 'entrypoint.sh'), ('apache-httpd.conf', 'httpd.conf')]:
        (fixture / destination).write_bytes((ROOT / source_name).read_bytes().replace(b'\r\n', b'\n'))
    results = {}
    for variant in ('baseline', 'patched'):
        print('VALIDATING ' + variant, flush=True)
        results[variant] = test_variant(variant, builds['dev_image'], fixture, poc)
        print(variant + ': ' + json.dumps({key: value['passed'] for key, value in results[variant]['checks'].items()}), flush=True)
    passed = all(result['passed'] for result in results.values())
    summary = {'status': 'APACHE_MITIGATION_DIFFERENTIAL_PASS' if passed else 'APACHE_DIFFERENTIAL_FAILED',
               'poc_sha256': SOURCE_HASH, 'rce_positive_control_established': results['baseline']['rce_proven'],
               'rce_patch_verified': passed and results['baseline']['rce_proven'] and not results['patched']['rce_proven'],
               'scope': 'Matched minimal PHP 7.4.33 and CalCyber 7.4.33-p1 Apache modules; finite lifecycle regressions.',
               'variants': results}
    (ROOT / ('apache-summary-' + RUN_ID + '.json')).write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: value for key, value in summary.items() if key != 'variants'}, indent=2))


if __name__ == '__main__':
    main()
