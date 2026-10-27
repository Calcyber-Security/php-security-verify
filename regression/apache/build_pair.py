"""Sequential offline builds of identical PHP 7.4 Apache configurations."""
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEV = 'calcyber-apache74-dev-20261026-v1'
RECORD = ROOT / 'apache-builds.json'


def docker(*args, timeout=60):
    return subprocess.check_output(['docker', *map(str, args)], timeout=timeout).decode()


state = json.loads(docker('inspect', DEV))[0]['State']
assert state['Status'] == 'exited' and state['ExitCode'] == 0 and not state['OOMKilled'], state
image = docker('commit', DEV).strip()
record = {'status': 'BUILDING', 'dev_image': image, 'builders': {}}
RECORD.write_text(json.dumps(record, indent=2) + '\n')
for variant in ('baseline', 'patched'):
    name = 'calcyber-apache74-' + variant + '-build-20261026-v1'
    docker('create', '--name', name, '--label', 'org.calcyber.purpose=apache-validation-build',
           '--network', 'none', '--memory', '2g', '--memory-swap', '2g', '--cpus', '1',
           '--pids-limit', '64', '--restart', 'no',
           '--tmpfs', '/work:rw,exec,nosuid,nodev,size=1073741824,mode=1777',
           '--log-driver', 'local', '--log-opt', 'max-size=2m', '--log-opt', 'max-file=1',
           '--log-opt', 'compress=false', '-e', 'LAB_VARIANT=' + variant,
           '--entrypoint', '/usr/bin/timeout', image, '1800', '/bin/sh', '/input/build-apache.sh')
    docker('start', name)
    started = time.monotonic()
    while True:
        state = json.loads(docker('inspect', name))[0]['State']
        if not state['Running']:
            break
        elapsed = round(time.monotonic() - started)
        print(f'{variant}: compiling, {elapsed}s', flush=True)
        if elapsed > 1840:
            docker('stop', '--time', '3', name)
            raise RuntimeError('Outer build deadline exceeded')
        time.sleep(30)
    logs = subprocess.run(['docker', 'logs', name], capture_output=True, timeout=30)
    (ROOT / ('apache-build-' + variant + '.log')).write_bytes(logs.stdout + logs.stderr)
    record['builders'][variant] = {'name': name, 'state': state,
                                   'elapsed_seconds': round(time.monotonic() - started)}
    RECORD.write_text(json.dumps(record, indent=2) + '\n')
    if state['ExitCode'] != 0 or state['OOMKilled']:
        raise RuntimeError('Build failed: ' + variant)
    destination = ROOT / ('apache-artifacts-' + variant)
    destination.mkdir(exist_ok=False)
    docker('cp', name + ':/artifacts/.', destination)
    print(variant + ': BUILD_COMPLETE', flush=True)
record['status'] = 'BOTH_BUILDS_COMPLETE'
RECORD.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, indent=2))
