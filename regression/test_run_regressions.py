import unittest
import run_regressions as lab


class EvidenceTests(unittest.TestCase):
    def test_arbitrary_child_failure_is_not_success(self):
        for code, output in [(1, 'syntax error'), (127, 'missing executable'),
                             (137, 'Killed'), (124, 'timeout')]:
            self.assertFalse(lab.oom_matches({'exit_code': code, 'stdout': output, 'stderr': ''}, 'patched'))

    def test_patch_oom_requires_all_markers(self):
        sample = {'exit_code': 1, 'stdout': 'CALCYBER_OOM_STARTED\n',
                  'stderr': 'Fatal error: Allowed memory size of 8388608 bytes exhausted'}
        self.assertTrue(lab.oom_matches(sample, 'patched'))
        for suffix in ['CALCYBER_SHUTDOWN_REACHED', 'CALCYBER_OOM_NOT_REACHED']:
            self.assertFalse(lab.oom_matches(dict(sample, stdout=sample['stdout'] + suffix), 'patched'))

    def test_wrong_cgi_endpoint_does_not_pass(self):
        self.assertIsNone(lab.endpoint_json({'exit_code': 0, 'stdout': 'Status: 200\n<html>OK</html>'}))
        self.assertIsNone(lab.endpoint_json({'exit_code': 1, 'stdout': 'CALCYBER_LAB_JSON={"marker":"CALCYBER_ISOLATED_LAB_CONTROL"}'}))

    def test_finite_multipart_fixture(self):
        body, boundary = lab.multipart([('one', '1'), ('two', '2'), ('three', '3')])
        self.assertLess(len(body), 2048)
        self.assertEqual(body.count(b'Content-Disposition:'), 3)
        self.assertTrue(body.endswith(f'--{boundary}--\r\n'.encode()))

    def test_post_control_ignores_only_deliberate_session_state(self):
        before = {'marker': 'control', 'version': '7.4.33', 'sapi': 'cgi-fcgi',
                  'fields': {'control': '1'}, 'file_count': 0, 'multipart_limit': '',
                  'session_progress_file': 'ABSENT'}
        after = dict(before, session_progress_file='PRESENT')
        self.assertTrue(lab.control_matches(after, before))
        self.assertFalse(lab.control_matches(dict(after, fields={}), before))
        self.assertFalse(lab.control_matches(dict(after, version='wrong'), before))

    def test_php74_warning_case_and_leading_article(self):
        output = ('Warning: Unknown: The session id is too long or contains illegal characters\n'
                  'Failed to read session data: files\nFailed to write session data (files)')
        self.assertEqual(lab.session_warning_markers(output), [True, True, True])
        self.assertEqual(lab.session_warning_markers('Failed to read session data'), [False, True, False])


if __name__ == '__main__':
    unittest.main()
