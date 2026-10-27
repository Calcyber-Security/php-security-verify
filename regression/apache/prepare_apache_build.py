"""Prepare a bounded Apache dev image; exploit runtime remains isolated."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
IMAGE = 'php@sha256:c9d7e608f73832673479770d66aacc8100011ec751d1905ff63fae3fe2e0ca6d'
NAME = 'calcyber-apache74-dev-20261026-v1'


def docker(*args):
    return subprocess.check_output(['docker', *map(str, args)], timeout=60).decode()


fixtures = ROOT / 'build-input'
fixtures.mkdir(exist_ok=False)
for name in ('setup-apache-dev.sh', 'build-apache.sh'):
    data = (ROOT / name).read_bytes().replace(b'\r\n', b'\n')
    (fixtures / name).write_bytes(data)
for name, expected in (
    ('mitigation.patch', 'ad8e568b543ee2d29a07d5df5cf7336616ebf145d156d9c8d4d4f0c1d9a90b1b'),
    ('version.patch', 'c9f4a7e7607a31f5f2043b8e6a7aa926655ca002be81580df2462cfe5a015324'),
):
    data = (ROOT.parents[1] / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == expected
    (fixtures / name).write_bytes(data)
docker('create', '--name', NAME, '--label', 'org.calcyber.purpose=apache-validation-build',
       '--memory', '2g', '--memory-swap', '2g', '--cpus', '1', '--pids-limit', '96',
       '--restart', 'no', '--log-driver', 'local', '--log-opt', 'max-size=2m',
       '--log-opt', 'max-file=1', '--log-opt', 'compress=false',
       '--entrypoint', '/usr/bin/timeout', IMAGE, '600', '/bin/sh', '/input/setup-apache-dev.sh')
docker('cp', fixtures, NAME + ':/input')
docker('start', NAME)
network_name = 'calcyber-rce-isolated-20261026'
network_check = subprocess.run(['docker', 'network', 'inspect', network_name],
                               capture_output=True, timeout=30)
if network_check.returncode:
    docker('network', 'create', '--internal', '--label',
           'org.calcyber.purpose=rce-validation', network_name)
network = json.loads(docker('network', 'inspect', network_name))[0]
assert network['Internal'] and network['Labels'].get('org.calcyber.purpose') == 'rce-validation'
print(json.dumps({'name': NAME, 'status': 'SETUP_STARTED', 'base_image': IMAGE}))
