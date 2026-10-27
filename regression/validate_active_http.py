#!/usr/bin/env python3
"""Developer validation: loopback HTTP -> disposable offline CGI child.

Requires the exact local runtime images recorded by the existing differential
lab. This adapter does not represent Apache/FPM persistent worker reuse.
"""
import argparse
import json
import subprocess
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify


def docker(*args, data=None, check=True):
    result = subprocess.run(['docker', *map(str, args)], input=data,
                            capture_output=True, timeout=30)
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode('utf-8', 'replace')[-1000:])
    return result


def run_variant(variant, root):
    source = json.loads((root / 'evidence' / variant / 'results.json').read_text())
    image = source['runtime_image']
    name = 'calcyber-active-http-' + variant + '-20261026-v1'
    docker('create', '--name', name, '--network', 'none', '--read-only',
           '--user', '65534:65534', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
           '--memory', '256m', '--memory-swap', '256m', '--cpus', '0.5', '--pids-limit', '32',
           '--restart', 'no', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16777216,mode=1777',
           '--log-driver', 'local', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1',
           '--log-opt', 'compress=false', '--entrypoint', '/bin/sh', image, '-c', 'exec sleep 600')
    spec = json.loads(docker('inspect', name).stdout)[0]
    config = spec['HostConfig']
    if (config['NetworkMode'] != 'none' or config['Memory'] != 268435456
            or config['MemorySwap'] != 268435456 or config['NanoCpus'] != 500000000
            or not config['ReadonlyRootfs'] or spec['Mounts'] or config.get('PortBindings')):
        raise RuntimeError('Unexpected container isolation')
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.respond(b'')

        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 <= size <= 1048576:
                self.send_error(413)
                return
            self.respond(self.rfile.read(size))

        def respond(self, body):
            env = {'REDIRECT_STATUS': '1', 'REQUEST_METHOD': self.command,
                   'SCRIPT_FILENAME': '/input/endpoint.php', 'SCRIPT_NAME': '/index.php',
                   'SERVER_PROTOCOL': 'HTTP/1.1', 'CONTENT_LENGTH': str(len(body)),
                   'CONTENT_TYPE': self.headers.get('Content-Type', ''),
                   'HTTP_COOKIE': self.headers.get('Cookie', '')}
            args = ['exec', '-i']
            for key, value in env.items():
                args.extend(['-e', f'{key}={value}'])
            args.extend([name, 'timeout', '15', '/opt/lab-php/bin/php-cgi', '-n'])
            for setting in ('memory_limit=128M', 'post_max_size=8M', 'display_errors=1',
                            'display_startup_errors=1', 'error_reporting=32767', 'html_errors=0',
                            'log_errors=0', 'session.save_path=/tmp', 'session.upload_progress.enabled=1'):
                args.extend(['-d', setting])
            result = docker(*args, data=body, check=False)
            headers, separator, content = result.stdout.partition(b'\r\n\r\n')
            status = 200
            if not separator:
                status, content = 502, b'CGI child produced no response'
            else:
                for line in headers.decode('latin1').splitlines():
                    if line.lower().startswith('status:'):
                        status = int(line.split()[1])
            self.send_response(status)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    try:
        docker('start', name)
        thread.start()
        target = verify.normalize_url(f'http://127.0.0.1:{server.server_port}/index.php')
        result = verify.scan(target, timeout=20)
        control_body, boundary = verify.control_body()
        control = verify.send(target, 'isolated-parser-control', 'POST', control_body, boundary, {}, 20)
        probe = verify.send(target, 'isolated-parser-probe', 'POST', verify.multipart_probe(1, 4000), '', {}, 20)
        post = verify.send(target, 'isolated-parser-post-health', 'GET', b'', '', {}, 20)
        verdict, reason = verify.classify(probe, control, post)
        from dataclasses import asdict
        result['independent_parser_test'] = {'verdict': verdict, 'reason': reason,
                                             'control': asdict(control), 'probe': asdict(probe), 'post': asdict(post)}
        result['validation_scope'] = 'Loopback HTTP/CGI adapter, one disposable CGI child per request; not persistent Apache/FPM.'
        return result
    finally:
        if thread.is_alive():
            server.shutdown()
            thread.join(timeout=5)
        server.server_close()
        docker('stop', '--time', '2', name, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Evidence output already exists')
    root = Path(__file__).resolve().parents[1]
    results = {variant: run_variant(variant, root) for variant in ('baseline', 'patched')}
    expected = {'baseline': ('LEGACY_SESSION_BEHAVIOR_OBSERVED', 'VULNERABLE_OOM_PATH_OBSERVED'),
                'patched': ('MITIGATION_BEHAVIOR_OBSERVED', 'MITIGATION_BEHAVIOR_OBSERVED')}
    passed = all((results[key]['verdict'], results[key]['independent_parser_test']['verdict']) == value
                 for key, value in expected.items())
    document = {'generated_utc': datetime.now(timezone.utc).isoformat(),
                'status': 'ACTIVE_HTTP_DIFFERENTIAL_PASS' if passed else 'ACTIVE_HTTP_DIFFERENTIAL_FAILED',
                'results': results}
    args.output.write_text(json.dumps(document, indent=2) + '\n')
    print(json.dumps({'status': document['status'], 'verdicts': {
        key: [value['verdict'], value['independent_parser_test']['verdict']] for key, value in results.items()}}, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
