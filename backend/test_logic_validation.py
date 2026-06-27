import unittest
from trust_score.engine import compute_trust_scores
from metrics.engine import _summarize


class TestLogicValidation(unittest.TestCase):

    def test_empty_events_returns_empty_dict(self):
        result = compute_trust_scores(events=[], incidents=[])
        self.assertEqual(result, {})

    def test_metrics_empty_data(self):
        summary = _summarize([])
        self.assertEqual(summary.count, 0)
        self.assertEqual(summary.mttd_mean, 0)
        self.assertEqual(summary.mttr_mean, 0)

    def test_metrics_handles_none_values(self):
        class MockIncident:
            mttd_minutes = None
            mttr_minutes = None

        summary = _summarize([MockIncident()])
        self.assertEqual(summary.count, 0)

if __name__ == "__main__":
    unittest.main()
