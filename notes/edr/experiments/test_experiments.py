"""Deterministic regression tests: mechanics and boundaries, NOT detection rates."""
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from cpu_emulator import run
from event_models import (detect_sequence, masked_offsets, match_audit,
                          resolve_process, response_step)
from fixtures import make_pe
from pe_heuristic_demo import analyze, entropy, ParseError


def event(eid, time, kind='process', **overrides):
    e = dict(id=eid, time=time, kind=kind, host='H1', boot='B1', pid=640,
             start=0, image='powershell.exe', parent_image='winword.exe', port=443)
    e.update(overrides)
    return e


class EmulatorTests(unittest.TestCase):
    def test_budget_boundary(self):
        self.assertEqual(run(8)['status'], 'BUDGET_EXHAUSTED')
        result = run(9)
        self.assertEqual((result['status'], result['data']), ('MATCH', '414243'))

    def test_exact_trace(self):
        trace = run(9)['trace']
        expected = {2: (6, 16, 3, '141716'), 3: (9, 16, 3, '411716'),
                    5: (6, 17, 2, '411716'), 8: (6, 18, 1, '414216'),
                    9: (9, 18, 1, '414243')}
        for step, values in expected.items():
            e = trace[step - 1]
            self.assertEqual((e['ip'], e['si'], e['cx'], e['data']), values)

    def test_unsupported_not_clean(self):
        self.assertEqual(run(code=b'\x90')['status'], 'UNSUPPORTED')

    def test_out_of_bounds(self):
        code = bytes.fromhex('BEFFFF B90100 803455')
        self.assertEqual(run(code=code)['status'], 'OUT_OF_BOUNDS')

    def test_halt_is_not_clean(self):
        self.assertEqual(run(code=b'\xF4')['status'], 'HALTED_NO_MATCH')

    def test_budget_validation(self):
        for value in [-1, 100001, True, 1.2]:
            with self.assertRaises(ValueError):
                run(value)
        self.assertEqual(run(0)['status'], 'BUDGET_EXHAUSTED')


class PatternTests(unittest.TestCase):
    def test_mask(self):
        pattern, mask = bytes.fromhex('B80000CD21'), [1, 0, 0, 1, 1]
        self.assertEqual(masked_offsets(bytes.fromhex('00B8FF00CD21'), pattern, mask), [1])
        self.assertEqual(masked_offsets(bytes.fromhex('B8FF00CD10'), pattern, mask), [])

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            masked_offsets(b'ABC', b'', [])

    def test_chunk_boundary(self):
        chunks = [b'xxAB', b'Cyy']
        self.assertEqual([masked_offsets(c, b'ABC', [1, 1, 1]) for c in chunks], [[], []])
        self.assertEqual(masked_offsets(b''.join(chunks), b'ABC', [1, 1, 1]), [2])


class IOCTests(unittest.TestCase):
    def test_object_boundaries(self):
        xml = '''<audits>
        <host id="A"><service name="MS 1atent time services"/></host>
        <host id="B"><file id="f1" name="bad.exe" size="6000"/></host>
        <host id="C"><file id="f2" name="bad.exe" size="12000"/>
                     <file id="f3" name="good.exe" size="6000"/></host></audits>'''
        result = match_audit(xml)
        self.assertTrue(result['A']['match'])
        self.assertEqual(result['B']['files'], ['f1'])
        self.assertFalse(result['C']['match'])

    def test_size_boundaries(self):
        for size, matched in [(4095, False), (4096, True), (10240, True), (10241, False)]:
            xml = f'<audits><host id="A"><file id="f" name="bad.exe" size="{size}"/></host></audits>'
            self.assertEqual(match_audit(xml)['A']['match'], matched)

    def test_duplicate_host(self):
        with self.assertRaises(ValueError):
            match_audit('<audits><host id="A"/><host id="A"/></audits>')

    def test_dtd_rejected(self):
        with self.assertRaises(ValueError):
            match_audit('<!DOCTYPE x><audits/>')


class SequenceTests(unittest.TestCase):
    def test_happy_path_and_interleaving(self):
        records = [event('E1', 0), event('E2', 2, 'network', pid=9),
                   event('E3', 5, 'network')]
        self.assertEqual(detect_sequence(records)[0]['evidence'], ['E1', 'E3'])

    def test_different_identity(self):
        for change in [dict(host='H2'), dict(boot='B2'), dict(pid=9), dict(start=1)]:
            self.assertEqual(detect_sequence([event('A', 0), event('B', 5, 'network', **change)]), [])

    def test_expiry_and_inclusive_boundary(self):
        self.assertEqual(len(detect_sequence([event('A', 0), event('B', 60, 'network')])), 1)
        self.assertEqual(detect_sequence([event('A', 0), event('B', 61, 'network')]), [])

    def test_exit_clears_state(self):
        self.assertEqual(detect_sequence([event('A', 0), event('X', 2, 'exit'), event('B', 3, 'network')]), [])

    def test_missing_identity(self):
        e = event('A', 0)
        del e['start']
        with self.assertRaises(ValueError):
            detect_sequence([e])

    def test_out_of_order(self):
        with self.assertRaises(ValueError):
            detect_sequence([event('A', 5), event('B', 1, 'network')])

    def test_duplicate_and_conflict(self):
        a, b = event('A', 0), event('B', 5, 'network')
        self.assertEqual(len(detect_sequence([a, a, b, b])), 1)
        with self.assertRaises(ValueError):
            detect_sequence([a, event('A', 0, pid=9)])

    def test_budget_exhaustion(self):
        with self.assertRaises(ValueError):
            detect_sequence([event('A', 0), event('B', 1, pid=9)], max_pending=1)

    def test_nonmatching_parent(self):
        self.assertEqual(detect_sequence([event('A', 0, parent_image='explorer.exe'), event('B', 5, 'network')]), [])

    def test_late_event_resolves_old_instance(self):
        old = dict(host='H', boot='B', pid=640, start=0, end=60, instance='OLD')
        new = dict(host='H', boot='B', pid=640, start=180, end=None, instance='NEW')
        self.assertEqual(resolve_process('H', 'B', 640, 20, [old, new]), 'OLD')
        old['end'] = None
        self.assertIsNone(resolve_process('H', 'B', 640, 200, [old, new]))


class PETests(unittest.TestCase):
    def test_entropy_extremes(self):
        self.assertEqual(entropy(b''), 0.0)
        self.assertEqual(entropy(b'x' * 1024), 0.0)
        self.assertEqual(entropy(bytes(range(256)) * 4), 8.0)

    def test_low_signal_is_not_clean_verdict(self):
        result = analyze(make_pe())
        self.assertEqual((result['score'], result['verdict']), (0, 'NO_RULE_HIT'))
        self.assertEqual(len(result['sha256']), 64)

    def test_high_entropy_rwx(self):
        result = analyze(make_pe(high_entropy=True, writable=True))
        self.assertEqual((result['score'], result['verdict']), (40, 'NEEDS_REVIEW'))

    def test_nonexec_entry(self):
        self.assertEqual(analyze(make_pe(high_entropy=True, executable=False))['score'], 45)

    def test_import_names_both_formats(self):
        for pe64 in [False, True]:
            result = analyze(make_pe(imports=True, pe64=pe64))
            self.assertEqual(result['imports'], ['CreateRemoteThread', 'WriteProcessMemory'])
            self.assertEqual(result['score'], 32)

    def test_zero_entry_does_not_flag_nonexec(self):
        self.assertEqual(analyze(make_pe(executable=False, entry=0))['score'], 0)

    def test_truncated_data(self):
        with self.assertRaises(ParseError):
            analyze(make_pe()[:-1])

    def test_invalid_header(self):
        for data in [b'ABC', bytes(1024), b'MZ' + bytes(1022)]:
            with self.assertRaises(ParseError):
                analyze(data)

    def test_zero_fill_not_file_offset(self):
        data = bytearray(make_pe())
        struct.pack_into('<I', data, 0x98 + 224 + 16, 0)
        with self.assertRaises(ParseError):
            analyze(data)

    def test_overlapping_sections_rejected(self):
        data = bytearray(make_pe())
        struct.pack_into('<H', data, 0x86, 2)
        s = 0x98 + 224
        data[s + 40:s + 80] = data[s:s + 40]
        with self.assertRaises(ParseError):
            analyze(data)

    def test_corrupt_import_directory(self):
        data = bytearray(make_pe(imports=True))
        struct.pack_into('<II', data, 0x98 + 96 + 8, 0xFFFFFF00, 40)
        with self.assertRaises(ParseError):
            analyze(data)

    def test_cli_failure_is_incomplete(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'bad.bin'
            path.write_bytes(b'MZ')
            run_result = subprocess.run([sys.executable, str(Path(__file__).with_name('pe_heuristic_demo.py')), str(path)], capture_output=True, text=True)
            self.assertEqual(run_result.returncode, 2)
            self.assertEqual(json.loads(run_result.stdout)['verdict'], 'ANALYSIS_INCOMPLETE')


class ResponseTests(unittest.TestCase):
    def test_ack_not_verified(self):
        state = response_step('queued', 'accepted')
        self.assertEqual(state, 'accepted')
        state = response_step(state, 'applied')
        self.assertEqual(state, 'reported')
        self.assertEqual(response_step(state, 'verify'), 'verified')

    def test_timeout_not_success(self):
        self.assertEqual(response_step('reported', 'timeout'), 'unknown')
        self.assertEqual(response_step('unknown', 'verify'), 'unknown')

    def test_delayed_ack_does_not_regress(self):
        self.assertEqual(response_step('verified', 'accepted'), 'verified')
        self.assertEqual(response_step('failed', 'applied'), 'failed')


if __name__ == '__main__':
    unittest.main()
