import json
import math
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from pe_heuristic_demo import (InvalidPE, PEFeatures, SectionFeatures, entropy,
                               parse_pe, score_features)
from tests.pe_fixtures import make_pe


def features(size=1024, h=6.0, write=False, execute=True, apis=(), ep=0):
    return PEFeatures((SectionFeatures(".text", size, h, write, execute),),
                      ep, frozenset(apis))


class RulesTests(unittest.TestCase):
    def check_score(self, value, expected):
        result = score_features(value)
        self.assertEqual(result.score, expected)
        self.assertEqual(result.verdict, "NEEDS_REVIEW" if expected >= 40 else "LOW_RISK")
        self.assertEqual(sum(hit.points for hit in result.hits), expected)

    def test_normal(self):
        self.check_score(features(), 0)

    def test_entropy_math(self):
        for data, expected in ((b"", 0), (b"a" * 1024, 0),
                               (bytes(range(128)) * 8, 7), (bytes(range(256)) * 4, 8)):
            with self.subTest(length=len(data), expected=expected):
                self.assertEqual(entropy(data), expected)

    def test_entropy_boundaries(self):
        for size, h, expected in ((1023, 8, 0), (1024, math.nextafter(7.2, 0), 0),
                                  (1024, 7.2, 20), (1024, math.nextafter(7.2, 8), 20),
                                  (1025, 8, 20), (0, 0, 0)):
            with self.subTest(size=size, entropy=h):
                self.check_score(features(size=size, h=h), expected)

    def test_permissions(self):
        for write, execute, expected in ((False, False, 0), (True, False, 0),
                                         (False, True, 0), (True, True, 20)):
            with self.subTest(write=write, execute=execute):
                self.check_score(features(write=write, execute=execute, ep=None), expected)

    def test_entrypoint(self):
        self.check_score(features(execute=False), 25)
        self.check_score(features(execute=False, ep=None), 0)
        self.check_score(PEFeatures((SectionFeatures("data", 512, 0, True, False),
                                    SectionFeatures("code", 512, 0, False, True)), 1), 0)

    def test_imports(self):
        for names, expected in (((), 0), (("WriteProcessMemory",), 14),
                                (("CreateRemoteThread",), 18),
                                (("WriteProcessMemory", "CreateRemoteThread"), 32),
                                (("WriteProcessMemory", "WriteProcessMemory"), 14),
                                (("writeprocessmemory", "WriteProcessMemoryEx"), 0)):
            with self.subTest(names=names):
                self.check_score(features(apis=names), expected)

    def test_threshold_39_and_40(self):
        self.check_score(features(execute=False, apis=("WriteProcessMemory",)), 39)
        self.check_score(features(h=8, write=True), 40)

    def test_sections_accumulate(self):
        section = SectionFeatures("same", 1024, 8, True, True)
        result = score_features(PEFeatures((section, section), 0))
        self.assertEqual(result.score, 80)
        self.assertEqual([h.section_index for h in result.hits], [0, 0, 1, 1])

    def test_invalid_features(self):
        for value in (features(size=-1), features(h=float("nan")), features(h=8.1),
                      features(ep=-1), features(ep=1)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                score_features(value)


class ParserTests(unittest.TestCase):
    def test_pe32_and_pe64_normal(self):
        for pe64 in (False, True):
            with self.subTest(pe64=pe64):
                value = parse_pe(make_pe(pe64=pe64))
                self.assertEqual(value.sections, features().sections)
                self.assertEqual(value.entrypoint_section, 0)
                self.assertEqual(value.imported_apis, frozenset())
                self.assertEqual(value.warnings, ())
                self.assertEqual(score_features(value).score, 0)

    def test_named_and_ordinal_imports(self):
        for pe64 in (False, True):
            with self.subTest(pe64=pe64):
                value = parse_pe(make_pe(pe64=pe64, imports=("WriteProcessMemory",
                                        "CreateRemoteThread", "WriteProcessMemory"), ordinal=True))
                self.assertEqual(value.imported_apis, {"WriteProcessMemory", "CreateRemoteThread"})
                self.assertEqual(score_features(value).score, 32)

    def test_end_to_end_thresholds(self):
        for kwargs, expected in ((dict(high_entropy=True, writable=True), 40),
                                 (dict(executable=False, imports=("WriteProcessMemory",)), 39)):
            with self.subTest(expected=expected):
                result = score_features(parse_pe(make_pe(**kwargs)))
                self.assertEqual(result.score, expected)
                self.assertEqual(result.verdict, "NEEDS_REVIEW" if expected == 40 else "LOW_RISK")

    def test_entrypoint_boundaries(self):
        self.assertIsNone(parse_pe(make_pe(entrypoint=0)).entrypoint_section)
        self.assertEqual(parse_pe(make_pe(entrypoint=0x13FF)).entrypoint_section, 0)
        for ep in (0x1400, 0xFFF, 0x9000):
            with self.subTest(ep=ep), self.assertRaises(InvalidPE):
                parse_pe(make_pe(entrypoint=ep))

    def test_virtual_tail_does_not_change_disk_entropy(self):
        data = bytearray(make_pe(entrypoint=0x1500))
        struct.pack_into("<I", data, 0x178 + 8, 0x800)
        value = parse_pe(bytes(data))
        self.assertEqual(value.sections[0].raw_size, 1024)
        self.assertEqual(value.sections[0].entropy, 6)
        self.assertEqual(value.entrypoint_section, 0)

    def test_invalid_input(self):
        valid = make_pe()
        for data in (b"", b"not a PE", b"MZ", valid[:0x100], valid[:-1]):
            with self.subTest(length=len(data)), self.assertRaises(InvalidPE):
                parse_pe(data)

    def test_size_limit(self):
        data = make_pe()
        with patch("pe_heuristic_demo.MAX_FILE_SIZE", len(data)):
            self.assertEqual(score_features(parse_pe(data)).score, 0)
            with self.assertRaises(InvalidPE):
                parse_pe(data + b"x")

    def test_incomplete_header_layout(self):
        for offset, fmt, replacement in ((0x84 + 16, "<H", 96),
                                          (0x98 + 92, "<I", 17),
                                          (0x98 + 60, "<I", 0x100)):
            data = bytearray(make_pe())
            struct.pack_into(fmt, data, offset, replacement)
            with self.subTest(offset=offset), self.assertRaises(InvalidPE):
                parse_pe(bytes(data))

    def test_invalid_import_directory_and_thunks(self):
        for offset, replacement in ((0x98 + 104, 0x900000), (0x640, 0x900000),
                                     (0x98 + 108, 0)):
            data = bytearray(make_pe(imports=("WriteProcessMemory",)))
            struct.pack_into("<I", data, offset, replacement)
            # Break both ILT and IAT so the parser cannot recover from the IAT.
            if offset == 0x640:
                struct.pack_into("<I", data, 0x680, replacement)
            with self.subTest(offset=offset), self.assertRaises(InvalidPE):
                parse_pe(bytes(data))

    def test_overlapping_sections(self):
        for offset, replacement in ((0x178 + 40 + 12, 0x1000), (0x178 + 40 + 20, 0x200)):
            data = bytearray(make_pe(imports=("WriteProcessMemory",)))
            struct.pack_into("<I", data, offset, replacement)
            with self.subTest(offset=offset), self.assertRaises(InvalidPE):
                parse_pe(bytes(data))


class CLITests(unittest.TestCase):
    def test_cli(self):
        script = Path(__file__).resolve().parents[1] / "pe_heuristic_demo.py"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sample.exe"
            for kwargs, score, verdict in (({}, 0, "LOW_RISK"),
                                          (dict(high_entropy=True, writable=True), 40, "NEEDS_REVIEW")):
                target.write_bytes(make_pe(**kwargs))
                result = subprocess.run([sys.executable, str(script), str(target)],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual((payload["score"], payload["verdict"]), (score, verdict))
                self.assertEqual(len(payload["sha256"]), 64)
            target.write_bytes(b"invalid")
            for path in (target, Path(directory) / "missing.exe", Path(directory)):
                result = subprocess.run([sys.executable, str(script), str(path)],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertEqual(json.loads(result.stderr)["status"], "ERROR")


if __name__ == "__main__":
    unittest.main()
