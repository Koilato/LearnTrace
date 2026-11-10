"""Deterministic PE32/PE32+ fixtures for static parsing only; never execute."""

import struct


def make_pe(*, pe64=False, writable=False, executable=True, high_entropy=False,
            imports=(), ordinal=False, entrypoint=0x1000):
    """Aligned headers, .text, optional .idata with ILT/IAT and null terminators.

    No compiler, downloads, randomness or executable launches are needed.
    Structural validity does not assert Windows loader/runtime compatibility.
    """
    opt_size = 240 if pe64 else 224
    section_count = 2 if imports or ordinal else 1
    data = bytearray(0x600 + (0x200 if section_count == 2 else 0))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if pe64 else 0x14C,
                     section_count, 0, 0, 0, opt_size, 0x23 if pe64 else 0x103)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B if pe64 else 0x10B)
    struct.pack_into("<III", data, opt + 4, 0x400,
                     0x200 if section_count == 2 else 0, 0)
    struct.pack_into("<II", data, opt + 16, entrypoint, 0x1000)
    if pe64:
        struct.pack_into("<Q", data, opt + 24, 0x140000000)
        struct.pack_into("<QQQQ", data, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
        directory_offset = opt + 112
    else:
        struct.pack_into("<II", data, opt + 24, 0x2000, 0x400000)
        struct.pack_into("<IIII", data, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
        directory_offset = opt + 96
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<H", data, opt + 40, 6)
    struct.pack_into("<H", data, opt + 48, 6)
    struct.pack_into("<II", data, opt + 56, 0x3000 if section_count == 2 else 0x2000, 0x200)
    struct.pack_into("<H", data, opt + 68, 3)
    struct.pack_into("<I", data, directory_offset - 4, 16)
    table = opt + opt_size
    flags = 0x40000020 | (0x80000000 if writable else 0) | (0x20000000 if executable else 0)
    struct.pack_into("<8sIIIIIIHHI", data, table, b".text", 0x400, 0x1000,
                     0x400, 0x200, 0, 0, 0, 0, flags)
    data[0x200:0x600] = bytes(range(256)) * 4 if high_entropy else bytes(range(64)) * 16
    if section_count == 2:
        struct.pack_into("<8sIIIIIIHHI", data, table + 40, b".idata", 0x200, 0x2000,
                         0x200, 0x600, 0, 0, 0, 0, 0xC0000040)
        struct.pack_into("<II", data, directory_offset + 8, 0x2000, 40)
        struct.pack_into("<IIIII", data, 0x600, 0x2040, 0, 0, 0x20C0, 0x2080)
        data[0x6C0:0x6CD] = b"KERNEL32.dll\0"
        width, fmt = (8, "<Q") if pe64 else (4, "<I")
        values, cursor = [], 0xE0
        for name in imports:
            encoded = name.encode("ascii") + b"\0"
            if cursor + 2 + len(encoded) > 0x200:
                raise ValueError("fixture import names too large")
            values.append(0x2000 + cursor)
            data[0x600 + cursor + 2:0x600 + cursor + 2 + len(encoded)] = encoded
            cursor += 2 + len(encoded)
            cursor += cursor % 2
        if ordinal:
            values.append((1 << (width * 8 - 1)) | 1)
        if len(values) > 7:
            raise ValueError("fixture thunk table too large")
        for index, value in enumerate(values):
            struct.pack_into(fmt, data, 0x640 + index * width, value)
            struct.pack_into(fmt, data, 0x680 + index * width, value)
    return bytes(data)
