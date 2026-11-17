#!/usr/bin/env python3
"""Regression tests for benchmark.py.

Run with:  python3 -m unittest test_benchmark -v

These tests make no network calls: benchmark.sanitize is monkeypatched.
"""

import contextlib
import io
import unittest

import benchmark


def make_case(has_pii=True, lang="EN", pii_type="email", ctx="general"):
    return {
        "text": "sample text",
        "lang": lang,
        "pii_type": pii_type,
        "has_pii": has_pii,
        "ctx": ctx,
    }


class ScoreCaseTests(unittest.TestCase):
    """Failed or malformed API responses must be errors, never passes."""

    def test_failed_request_on_negative_control_is_error_not_tn(self):
        outcome, risk = benchmark.score_case(make_case(has_pii=False), None)
        self.assertEqual(outcome, "error")
        self.assertEqual(risk, "REQUEST_FAILED")

    def test_failed_request_on_positive_control_is_error(self):
        outcome, _ = benchmark.score_case(make_case(has_pii=True), None)
        self.assertEqual(outcome, "error")

    def test_response_missing_risk_category_is_error_not_clean(self):
        outcome, risk = benchmark.score_case(
            make_case(has_pii=False), {"safety_score": 0.0, "entities": []}
        )
        self.assertEqual(outcome, "error")
        self.assertEqual(risk, "MISSING_RISK_CATEGORY")

    def test_successful_classifications_unchanged(self):
        cases = [
            (True, "PRIVATE", "tp"),
            (True, "CRITICAL", "tp"),
            (True, "CLEAN", "fn"),
            (False, "CLEAN", "tn"),
            (False, "SENSITIVE", "fp"),
            (False, "CRITICAL", "fp"),
        ]
        for has_pii, risk, expected in cases:
            with self.subTest(has_pii=has_pii, risk=risk):
                outcome, _ = benchmark.score_case(
                    make_case(has_pii=has_pii), {"risk_category": risk}
                )
                self.assertEqual(outcome, expected)


class FailedRunTests(unittest.TestCase):
    """A run in which every API call fails must not look like a passing run."""

    def setUp(self):
        self._original = benchmark.sanitize
        benchmark.sanitize = lambda text, context="general": (None, 0)

    def tearDown(self):
        benchmark.sanitize = self._original

    def run_captured(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            summary = benchmark.run_benchmark()
        return out.getvalue(), summary

    def test_all_failures_are_counted_as_errors(self):
        text, summary = self.run_captured()
        self.assertEqual(summary["errors"], len(benchmark.CORPUS))
        self.assertEqual(summary["successful"], 0)
        self.assertIn(f"ERR: {len(benchmark.CORPUS)}", text)

    def test_failed_negative_controls_are_not_true_negatives(self):
        text, _ = self.run_captured()
        # All 10 negative controls failed; they must not be scored as TN.
        self.assertNotIn("TN: 10", text)
        self.assertIn("TN: 0", text)

    def test_win_condition_not_evaluated_on_failed_run(self):
        text, _ = self.run_captured()
        self.assertIn("Not evaluated", text)
        self.assertNotIn("(target ≤0.05)", text)

    def test_incomplete_run_is_not_declared_complete(self):
        text, _ = self.run_captured()
        self.assertIn("Benchmark incomplete", text)
        self.assertNotIn("✅ Benchmark complete.", text)


if __name__ == "__main__":
    unittest.main()
