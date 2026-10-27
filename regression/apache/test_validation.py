"""Guard against accepting a missing or mismatched corruption control."""
import copy
import json
import unittest
from pathlib import Path

from validate_apache_pair import corruption_chain_matches


class CorruptionControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        evidence = Path(__file__).resolve().parents[2] / 'evidence' / 'apache-mitigation.json'
        cls.variants = json.loads(evidence.read_text())['variants']

    def case(self, variant):
        return copy.deepcopy(self.variants[variant]['checks']['exploit_producer_consumer'])

    def test_actual_matched_observations(self):
        for variant in ('baseline', 'patched'):
            with self.subTest(variant=variant):
                self.assertTrue(corruption_chain_matches(self.case(variant), variant))

    def test_worker_failure_without_corruption_is_not_positive(self):
        case = self.case('baseline')
        case['segmentation_faults'] = case['heap_corruptions'] = 0
        self.assertFalse(corruption_chain_matches(case, 'baseline'))

    def test_different_worker_cannot_establish_cross_request_control(self):
        case = self.case('baseline')
        case['observations'][1]['worker_before'] = ['unrelated-worker']
        self.assertFalse(corruption_chain_matches(case, 'baseline'))

    def test_surviving_corrupt_worker_cannot_establish_patched_exit(self):
        case = self.case('patched')
        case['observations'][0]['worker_after'] = case['observations'][0]['worker_before']
        self.assertFalse(corruption_chain_matches(case, 'patched'))

    def test_corruption_on_patched_build_is_a_failure(self):
        case = self.case('patched')
        case['heap_corruptions'] = 1
        self.assertFalse(corruption_chain_matches(case, 'patched'))


if __name__ == '__main__':
    unittest.main()
