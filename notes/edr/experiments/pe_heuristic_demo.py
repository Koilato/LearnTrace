"""Read-only, bounded PE32/PE32+ teaching scanner using only Python stdlib.

Not a Windows loader, production malware detector, or historical product source.
Unsupported/malformed inputs raise ParseError, never a clean verdict.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

MAX_BYTES = 16 * 1024 * 1024
EXECUTE, WRITE = 0x20000000, 0x80000000


class ParseError(ValueError):
    pass


def entropy(data):
    if not data:
        return 0.0
    return -sum((n / len(data)) * math.log2(n / len(data))
                for n in Counter(data).values())


def analyze(data):
    if not 64 <= len(data) <= MAX_BYTES:
        raise ParseError('input size outside teaching parser limits')

    def read(offset, width):
        if offset < 0 or width < 0 or offset + width > len(data):
            raise ParseError('truncated or out-of-bounds field')
        return data[offset:offset + width]

    def unpack(fmt, offset):
        return struct.unpack(fmt, read(offset, struct.calcsize(fmt)))[0]

    if read(0, 2) != b'MZ':
        raise ParseError('missing MZ')
    pe = unpack('<I', 0x3C)
    if pe < 64 or read(pe, 4) != b'PE\0\0':
        raise ParseError('missing PE signature or invalid e_lfanew')
    count, optional_size = unpack('<H', pe + 6), unpack('<H', pe + 20)
    if not 1 <= count <= 96:
        raise ParseError('section count outside supported range')
    opt = pe + 24
    read(opt, optional_size)
    magic = unpack('<H', opt)
    layouts = {0x10B: (92, 96, 4), 0x20B: (108, 112, 8)}
    if magic not in layouts:
        raise ParseError('only PE32 and PE32+ supported')
    nr_offset, directory_offset, word_size = layouts[magic]
    if optional_size < directory_offset:
        raise ParseError('short optional header')
    entry = unpack('<I', opt + 16)
    header_size = unpack('<I', opt + 60)
    table = opt + optional_size
    if header_size < table + count * 40 or header_size > len(data):
        raise ParseError('invalid SizeOfHeaders')
    read(table, count * 40)
    sections = []
    for i in range(count):
        off = table + i * 40
        name = read(off, 8).split(b'\0', 1)[0].decode('ascii', errors='replace')
        virtual_size, rva, raw_size, raw = struct.unpack('<IIII', read(off + 8, 16))
        flags = unpack('<I', off + 36)
        span = max(virtual_size, raw_size)
        if raw_size:
            read(raw, raw_size)
            if raw < header_size:
                raise ParseError('raw section overlaps headers')
        if span and (rva < header_size or rva + span > 0x100000000):
            raise ParseError('unsupported virtual section range')
        for prior in sections:
            if span and prior['span'] and max(rva, prior['rva']) < min(rva + span, prior['rva'] + prior['span']):
                raise ParseError('overlapping virtual sections')
            if raw_size and prior['raw_size'] and max(raw, prior['raw']) < min(raw + raw_size, prior['raw'] + prior['raw_size']):
                raise ParseError('overlapping raw sections')
        sections.append(dict(name=name, rva=rva, span=span, raw=raw,
                             raw_size=raw_size, flags=flags,
                             entropy=entropy(read(raw, raw_size)) if raw_size else 0.0))

    def rva_to_offset(rva, width=1):
        if rva < header_size and rva + width <= header_size:
            return rva
        candidates = [s for s in sections
                      if s['rva'] <= rva and rva + width <= s['rva'] + s['span']]
        if len(candidates) != 1:
            raise ParseError('unmapped or ambiguous RVA')
        s = candidates[0]
        delta = rva - s['rva']
        if delta + width > s['raw_size']:
            raise ParseError('RVA is not backed by file bytes')
        return s['raw'] + delta

    def ascii_string(rva):
        out = bytearray()
        for i in range(512):
            byte = data[rva_to_offset(rva + i)]
            if byte == 0:
                try:
                    return out.decode('ascii')
                except UnicodeDecodeError as error:
                    raise ParseError('non-ASCII import name') from error
            out.append(byte)
        raise ParseError('unterminated or oversized import name')

    imported = set()
    directories = unpack('<I', opt + nr_offset)
    if directories > (optional_size - directory_offset) // 8:
        raise ParseError('directory count exceeds optional header')
    if directories >= 2:
        import_rva, import_size = struct.unpack('<II', read(opt + directory_offset + 8, 8))
        if bool(import_rva) != bool(import_size):
            raise ParseError('incomplete import directory')
        if import_rva:
            terminated = False
            for i in range(min(import_size // 20, 256)):
                fields = struct.unpack('<IIIII', read(rva_to_offset(import_rva + i * 20, 20), 20))
                if not any(fields):
                    terminated = True
                    break
                original, _, _, dll_name, first = fields
                ascii_string(dll_name)
                thunk = original or first
                if not thunk:
                    raise ParseError('missing import lookup table')
                for j in range(4096):
                    value = unpack('<I' if word_size == 4 else '<Q',
                                   rva_to_offset(thunk + j * word_size, word_size))
                    if value == 0:
                        break
                    if value & (1 << (word_size * 8 - 1)):
                        continue  # imported by ordinal: no API name available
                    if value > 0xFFFFFFFF:
                        raise ParseError('unsupported bound or malformed thunk')
                    rva_to_offset(value, 2)  # IMAGE_IMPORT_BY_NAME hint
                    imported.add(ascii_string(value + 2))
                else:
                    raise ParseError('import thunk budget exhausted')
            if not terminated:
                raise ParseError('import descriptors unterminated or budget exhausted')

    signals = []
    def add(rule, weight, detail):
        signals.append({'rule': rule, 'weight': weight, 'detail': detail})

    for s in sections:
        if s['raw_size'] >= 1024 and s['entropy'] >= 7.2:
            add('HIGH_ENTROPY', 20, s['name'])
        if s['flags'] & WRITE and s['flags'] & EXECUTE:
            add('RWX_SECTION', 20, s['name'])
    if entry:
        matches = [s for s in sections if s['rva'] <= entry < s['rva'] + s['span']]
        if len(matches) != 1:
            raise ParseError('entry point not in a supported section')
        rva_to_offset(entry)
        if not matches[0]['flags'] & EXECUTE:
            add('ENTRY_NOT_EXECUTABLE', 25, matches[0]['name'])
    for api, weight in [('WriteProcessMemory', 14), ('CreateRemoteThread', 18)]:
        if api in imported:
            add('IMPORTED_API', weight, api)
    score = sum(s['weight'] for s in signals)
    return {'sha256': hashlib.sha256(data).hexdigest(), 'score': score,
            'verdict': 'NEEDS_REVIEW' if score >= 40 else 'NO_RULE_HIT',
            'signals': signals, 'imports': sorted(imported), 'sections': sections,
            'coverage': 'static headers/sections/standard imports only; no execution, TLS, delay imports or runtime resolution'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    args = parser.parse_args()
    try:
        with args.path.open('rb') as file:
            data = file.read(MAX_BYTES + 1)
        result = analyze(data)
    except (OSError, ParseError) as error:
        print(json.dumps({'verdict': 'ANALYSIS_INCOMPLETE', 'error': str(error)}))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
