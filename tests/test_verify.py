import contextlib
import io
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verify


def response(label='', method='GET', **kwargs):
    return verify.Exchange(label, method, status=200, body_bytes=20, **kwargs)


class ActiveTests(unittest.TestCase):
    def test_no_authorization_ack_means_no_requests(self):
        with patch.object(verify, 'scan') as scanner, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                verify.main(['https://example.invalid/index.php'])
        scanner.assert_not_called()

    def test_no_clean_or_version_based_pass(self):
        for version in ('7.4.33-p1', '8.4.27', None):
            result, _ = verify.classify(response(php_version_reported=version), response(), response())
            self.assertEqual(result, 'NO_VULNERABLE_BEHAVIOR_OBSERVED')

    def test_all_session_warning_categories_needed(self):
        def fake(target, label, method, body, boundary, headers, timeout):
            return response(label, method, session_warning=label == 'session-lifecycle')
        result = verify.scan(verify.normalize_url('https://example.invalid/'), transport=fake)
        self.assertEqual(result['verdict'], 'LEGACY_SESSION_BEHAVIOR_OBSERVED')
        self.assertEqual(result['requests'], 4)
        self.assertFalse(result['rce_proven'])
        self.assertFalse(result['patch_verified'])

    def test_control_failure_stops_before_probe(self):
        labels = []
        def fake(target, label, method, body, boundary, headers, timeout):
            labels.append(label)
            return verify.Exchange(label, method, status=403)
        result = verify.scan(verify.normalize_url('https://example.invalid/'), transport=fake)
        self.assertEqual(labels, ['pre-health'])
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')

    def test_429_stops_immediately(self):
        labels = []
        def fake(target, label, method, body, boundary, headers, timeout):
            labels.append(label)
            return verify.Exchange(label, method, status=429) if label == 'session-lifecycle' else response(label, method)
        result = verify.scan(verify.normalize_url('https://example.invalid/'), transport=fake)
        self.assertEqual(labels, ['pre-health', 'multipart-control', 'session-lifecycle'])
        self.assertEqual(result['verdict'], 'RATE_LIMITED')

    def test_probe_redirect_is_not_a_vulnerability(self):
        probe = verify.Exchange('probe', 'POST', status=302, session_warning=True)
        self.assertEqual(verify.classify(probe, response(), None)[0], 'INCONCLUSIVE')

    def test_worker_failure_is_not_rce(self):
        probe = verify.Exchange('probe', 'POST', status=502)
        self.assertEqual(verify.classify(probe, response(), response())[0], 'WORKER_FAILURE_SUSPECTED')

    def test_failed_post_health_is_not_a_clean_result(self):
        post = verify.Exchange('health', 'GET', status=503)
        self.assertEqual(verify.classify(response(), response(), post)[0], 'HEALTH_CHECK_FAILED')

    def test_bounded_default_and_stop_on_mitigation(self):
        labels = []
        sizes = []
        def fake(target, label, method, body, boundary, headers, timeout):
            labels.append(label)
            sizes.append(len(body))
            return response(label, method, multipart_limit_warning=label.startswith('multipart-1MiB'))
        result = verify.scan(verify.normalize_url('https://example.invalid/'), extended=True, transport=fake)
        self.assertEqual(result['verdict'], 'MITIGATION_BEHAVIOR_OBSERVED')
        self.assertEqual(result['requests'], 6)
        self.assertLessEqual(max(sizes), 1048576)

    def test_extended_budget_and_no_result_claim_upgrade(self):
        def fake(target, label, method, body, boundary, headers, timeout):
            return response(label, method)
        result = verify.scan(verify.normalize_url('https://example.invalid/'), extended=True, transport=fake)
        self.assertEqual(result['requests'], 10)
        self.assertEqual(result['verdict'], 'NO_VULNERABLE_BEHAVIOR_OBSERVED')

    def test_session_only_omits_oom(self):
        def fake(target, label, method, body, boundary, headers, timeout):
            self.assertNotIn('MiB', label)
            return response(label, method)
        result = verify.scan(verify.normalize_url('https://example.invalid/'), session_only=True, transport=fake)
        self.assertEqual(result['requests'], 4)

    def test_output_omits_url_path_query_and_secrets(self):
        def fake(target, label, method, body, boundary, headers, timeout):
            return response(label, method)
        result = verify.scan(verify.normalize_url('https://example.invalid/private?token=secret'),
                             headers={'Authorization': 'Bearer secret'}, transport=fake)
        serialized = json.dumps(result)
        self.assertNotIn('secret', serialized)
        self.assertNotIn('/private', serialized)
        self.assertNotIn('Authorization', serialized)

    def test_header_file_rejects_request_smuggling(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'headers.json'
            for headers in ({'Transfer-Encoding': 'chunked'}, {'X-Test': 'value\r\nInjected: x'},
                            {'Cookie': 'a', 'cookie': 'b'}, {'Content-Type': 'text/plain'}):
                path.write_text(json.dumps(headers))
                with self.assertRaises(ValueError):
                    verify.load_headers(path)

    def test_credentials_and_control_characters_rejected(self):
        for url in ('https://user:secret@example.invalid/', 'https://example.invalid/#fragment',
                    'ftp://example.invalid/', 'https://example.invalid/\r\nX: y'):
            with self.assertRaises(ValueError):
                verify.normalize_url(url)

    def test_documented_payload_shape_is_finite(self):
        body = verify.multipart_probe(1, 4000)
        self.assertLessEqual(len(body), 1048576)
        self.assertEqual(body.count(b'Content-Disposition:name='), 4000)
        with self.assertRaises(ValueError):
            verify.multipart_probe(100, 4000)

    def test_preexisting_error_does_not_become_probe_evidence(self):
        def fake(target, label, method, body, boundary, headers, timeout):
            return response(label, method, startup_oom=True)
        result = verify.scan(verify.normalize_url('https://example.invalid/'), transport=fake)
        self.assertEqual(result['requests'], 1)
        self.assertEqual(result['verdict'], 'INCONCLUSIVE')


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.visited = []
        visited = self.visited
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                visited.append(self.path)
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', '/must-not-follow')
                    self.end_headers()
                    return
                data = b'x' * (verify.RESPONSE_LIMIT + 50) if self.path == '/large' else b'PHP control'
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            def do_POST(self):
                visited.append(self.path)
                body = self.rfile.read(int(self.headers['Content-Length']))
                data = ((b'The session id is too long or contains illegal characters\n'
                         b'Failed to read session data\nFailed to write session data (files)')
                        if b'PHP_SESSION_UPLOAD_PROGRESS' in body else b'PHP control')
                self.send_response(200)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_native_http_does_not_follow_redirect(self):
        result = verify.send(verify.normalize_url(self.url + '/redirect'), 'control', 'GET', b'', '', {}, 3)
        self.assertEqual(result.status, 302)
        self.assertEqual(self.visited, ['/redirect'])

    def test_native_http_body_is_capped(self):
        result = verify.send(verify.normalize_url(self.url + '/large'), 'control', 'GET', b'', '', {}, 3)
        self.assertTrue(result.response_truncated)
        self.assertEqual(result.body_bytes, verify.RESPONSE_LIMIT)

    def test_real_http_requests_exercise_active_flow(self):
        result = verify.scan(verify.normalize_url(self.url + '/index.php'), timeout=3)
        self.assertEqual(result['verdict'], 'LEGACY_SESSION_BEHAVIOR_OBSERVED')
        self.assertEqual(len(self.visited), 4)


if __name__ == '__main__':
    unittest.main()
