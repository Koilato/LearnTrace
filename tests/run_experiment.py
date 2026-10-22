"""Run tests and emit input/expected/actual evidence; invoke from repository root."""

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import unittest

import pefile

from pe_heuristic_demo import InvalidPE, parse_pe, score_features
from tests.pe_fixtures import make_pe
from tests.test_pe_heuristic_demo import features


def main():
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.discover("tests")
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    records = []
    for label, kwargs, expected in (
        ("normal_pe32", {}, 0), ("normal_pe64", {"pe64": True}, 0),
        ("high_entropy_rwx", {"high_entropy": True, "writable": True}, 40),
        ("nonexec_ep_wpm", {"executable": False, "imports": ("WriteProcessMemory",)}, 39),
        ("both_apis", {"pe64": True, "imports": ("WriteProcessMemory", "CreateRemoteThread")}, 32),
    ):
        data = make_pe(**kwargs)
        actual = asdict(score_features(parse_pe(data)))
        verdict = "NEEDS_REVIEW" if expected >= 40 else "LOW_RISK"
        records.append({"input": label, "fixture_parameters": kwargs,
                        "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                        "expected": {"score": expected, "verdict": verdict}, "actual": actual,
                        "passed": actual["score"] == expected and actual["verdict"] == verdict})
    for label, kwargs, expected in (
        ("entropy_size_below", {"size": 1023, "h": 8}, 0),
        ("entropy_below", {"h": 7.199999999999999}, 0),
        ("entropy_equal", {"h": 7.2}, 20),
        ("entropy_above", {"h": 7.200000000000001}, 20),
        ("write_only", {"write": True, "execute": False, "ep": None}, 0),
        ("execute_only", {}, 0), ("write_execute", {"write": True}, 20),
        ("nonexec_entrypoint", {"execute": False}, 25),
        ("wpm", {"apis": ("WriteProcessMemory",)}, 14),
        ("crt", {"apis": ("CreateRemoteThread",)}, 18),
    ):
        actual = asdict(score_features(features(**kwargs)))
        records.append({"input": label, "feature_overrides": kwargs,
                        "expected_score": expected, "actual": actual,
                        "passed": actual["score"] == expected})
    for label, data in (("empty", b""), ("non_pe", b"not a PE"),
                        ("truncated_section", make_pe()[:-1])):
        try:
            parse_pe(data)
            actual = "unexpected_success"
        except InvalidPE:
            actual = "InvalidPE"
        records.append({"input": label, "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "expected": "InvalidPE", "actual": actual,
                        "passed": actual == "InvalidPE"})
    report = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version, "implementation": platform.python_implementation(),
        "platform": platform.platform(), "pefile": pefile.__version__,
        "command": "python -m tests.run_experiment",
        "source_sha256": {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in (Path("pe_heuristic_demo.py"), Path("tests/pe_fixtures.py"),
                                    Path("tests/test_pe_heuristic_demo.py"), Path(__file__).relative_to(Path.cwd()))},
        "tests_run": result.testsRun, "test_success": result.wasSuccessful(),
        "test_output": stream.getvalue(), "cases": records,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if result.wasSuccessful() and all(r["passed"] for r in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
