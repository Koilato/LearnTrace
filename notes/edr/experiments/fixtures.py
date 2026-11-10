"""Synthetic PE-shaped parser fixtures, NOT validated Windows executables.

No malware, downloading or execution. Writes .bin fixtures only on explicit request.
"""
import argparse
from pathlib import Path
import struct


def make_pe(high_entropy=False, executable=True, writable=False,
            imports=False, pe64=False, entry=0x1000):
    opt_size = 240 if pe64 else 224
    data = bytearray(0x1200)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3C, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664 if pe64 else 0x14C,
                     1, 0, 0, 0, opt_size, 0x0022 if pe64 else 0x0102)
    opt = 0x98
    struct.pack_into('<H', data, opt, 0x20B if pe64 else 0x10B)
    struct.pack_into('<I', data, opt + 16, entry)
    struct.pack_into('<II', data, opt + 32, 0x1000, 0x200)
    struct.pack_into('<II', data, opt + 56, 0x2000, 0x200)
    struct.pack_into('<I', data, opt + (108 if pe64 else 92), 16)
    section = opt + opt_size
    data[section:section + 8] = b'.text\0\0\0'
    struct.pack_into('<IIII', data, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    flags = 0x40000020 | (0x20000000 if executable else 0) | (0x80000000 if writable else 0)
    struct.pack_into('<I', data, section + 36, flags)
    data[0x200:] = bytes(range(256)) * 16 if high_entropy else b'\0' * 4096
    if imports:
        directory = opt + (112 if pe64 else 96)
        struct.pack_into('<II', data, directory + 8, 0x1100, 40)
        data[0x300:0x328] = bytes(40)
        struct.pack_into('<IIIII', data, 0x300, 0x1140, 0, 0, 0x1180, 0x1140)
        struct.pack_into('<QQQ' if pe64 else '<III', data, 0x340, 0x1200, 0x1240, 0)
        dll = b'KERNEL32.dll\0'
        data[0x380:0x380 + len(dll)] = dll
        for offset, api in [(0x400, b'WriteProcessMemory'), (0x440, b'CreateRemoteThread')]:
            name = b'\0\0' + api + b'\0'
            data[offset:offset + len(name)] = name
    return bytes(data)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    samples = {'low_signal.bin': make_pe(),
               'high_entropy_rwx.bin': make_pe(high_entropy=True, writable=True),
               'nonexec_entry.bin': make_pe(high_entropy=True, executable=False),
               'two_imports.bin': make_pe(imports=True)}
    for name, content in samples.items():
        path = args.out / name
        with path.open('xb') as file:
            file.write(content)
        print(path)
