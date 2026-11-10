"""Teaching-only static PE heuristics. Never loads or executes the scanned file."""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import sys

MAX_FILE_SIZE = 64 * 1024 * 1024
REVIEW_THRESHOLD = 40


class InvalidPE(ValueError):
    """Invalid, incomplete, or unsupported input; no risk verdict is available."""


@dataclass(frozen=True)
class SectionFeatures:
    name: str
    raw_size: int
    entropy: float
    writable: bool
    executable: bool


@dataclass(frozen=True)
class PEFeatures:
    sections: tuple[SectionFeatures, ...]
    entrypoint_section: int | None
    imported_apis: frozenset[str] = frozenset()
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class Hit:
    rule: str
    points: int
    section_index: int | None = None


@dataclass(frozen=True)
class Assessment:
    score: int
    verdict: str
    hits: tuple[Hit, ...]


def entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte; empty input has entropy zero."""
    if not data:
        return 0.0
    return -sum((n / len(data)) * math.log2(n / len(data))
                for n in Counter(data).values())


def score_features(features: PEFeatures) -> Assessment:
    """Pure scoring: section hits accumulate; named API hits count once each."""
    hits = []
    for index, section in enumerate(features.sections):
        if section.raw_size < 0 or not 0 <= section.entropy <= 8:
            raise ValueError("invalid section features")
        if section.raw_size >= 1024 and section.entropy >= 7.2:
            hits.append(Hit("high_entropy", 20, index))
        if section.writable and section.executable:
            hits.append(Hit("writable_executable", 20, index))
    ep = features.entrypoint_section
    if ep is not None:
        if not 0 <= ep < len(features.sections):
            raise ValueError("invalid entrypoint section index")
        if not features.sections[ep].executable:
            hits.append(Hit("non_executable_entrypoint", 25, ep))
    for api, points in (("WriteProcessMemory", 14), ("CreateRemoteThread", 18)):
        if api in features.imported_apis:
            hits.append(Hit(api, points))
    total = sum(hit.points for hit in hits)
    return Assessment(total, "NEEDS_REVIEW" if total >= REVIEW_THRESHOLD
                      else "LOW_RISK", tuple(hits))


def parse_pe(data: bytes) -> PEFeatures:
    """Extract disk features with pefile; not a full Windows loader validator.

    Only standard named imports are scored. Ordinal, delayed and runtime
    imports are not resolved. Reject partial import parsing instead of silently
    treating missing features as benign. Other pefile warnings remain visible.
    """
    import pefile

    if not data or len(data) > MAX_FILE_SIZE:
        raise InvalidPE("empty input or file exceeds 64 MiB limit")
    try:
        with pefile.PE(data=data, fast_load=True) as pe:
            if pe.OPTIONAL_HEADER.Magic not in (0x10B, 0x20B):
                raise InvalidPE("only PE32 and PE32+ are supported")
            if not pe.sections or len(pe.sections) != pe.FILE_HEADER.NumberOfSections:
                raise InvalidPE("missing or incomplete section table")
            directory_base = 112 if pe.OPTIONAL_HEADER.Magic == 0x20B else 96
            directory_count = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            optional_size = pe.FILE_HEADER.SizeOfOptionalHeader
            section_table_end = (pe.DOS_HEADER.e_lfanew + 24 + optional_size
                                 + 40 * pe.FILE_HEADER.NumberOfSections)
            if (directory_count > 16 or optional_size < directory_base + 8 * directory_count
                    or section_table_end > pe.OPTIONAL_HEADER.SizeOfHeaders):
                raise InvalidPE("incomplete or unsupported header layout")
            if pe.OPTIONAL_HEADER.SizeOfHeaders > len(data):
                raise InvalidPE("truncated headers")
            sections, spans, raw_spans = [], [], []
            for section in pe.sections:
                start, size = section.PointerToRawData, section.SizeOfRawData
                if size and (start < pe.OPTIONAL_HEADER.SizeOfHeaders
                             or start + size > len(data)):
                    raise InvalidPE("section raw data outside file bounds")
                if size:
                    raw_spans.append((start, start + size))
                # Disk bytes only: do not include zero-filled virtual tails.
                raw = data[start:start + size] if size else b""
                sections.append(SectionFeatures(
                    section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
                    len(raw), entropy(raw), bool(section.Characteristics & 0x80000000),
                    bool(section.Characteristics & 0x20000000)))
                va = section.VirtualAddress
                spans.append((va, va + max(section.Misc_VirtualSize, size)))
            for ranges in (spans, raw_spans):
                ordered = sorted((a, b) for a, b in ranges if b > a)
                if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
                    raise InvalidPE("overlapping sections are unsupported")
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            matches = [i for i, (a, b) in enumerate(spans) if a <= ep < b]
            if ep and len(matches) != 1:
                raise InvalidPE("entrypoint does not map to one section")
            # A zero entrypoint (e.g. resource-only DLL) has no entrypoint rule.
            ep_index = matches[0] if ep else None
            before = len(pe.get_warnings())
            pe.parse_data_directories(directories=[1])
            import_warnings = pe.get_warnings()[before:]
            if import_warnings:
                raise InvalidPE("incomplete import parsing: " + "; ".join(import_warnings))
            directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
            if len(directories) > 1:
                imp = directories[1]
                if bool(imp.VirtualAddress) != bool(imp.Size):
                    raise InvalidPE("inconsistent import directory")
                if imp.VirtualAddress and not getattr(pe, "DIRECTORY_ENTRY_IMPORT", None):
                    raise InvalidPE("declared import directory could not be parsed")
            apis = frozenset(symbol.name.decode("ascii")
                             for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ())
                             for symbol in dll.imports if symbol.name is not None)
            warnings = list(pe.get_warnings())
            if not ep:
                warnings.append("No entrypoint: entrypoint rule skipped.")
            if len(directories) > 13 and directories[13].VirtualAddress:
                warnings.append("Delay imports are outside this demo's scope.")
            return PEFeatures(tuple(sections), ep_index, apis, tuple(warnings))
    except (pefile.PEFormatError, UnicodeDecodeError) as exc:
        raise InvalidPE(str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="PE file to read, never execute")
    args = parser.parse_args(argv)
    try:
        with args.file.open("rb") as handle:
            data = handle.read(MAX_FILE_SIZE + 1)
        features = parse_pe(data)
        assessment = score_features(features)
    except (OSError, InvalidPE, ImportError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}), file=sys.stderr)
        return 2
    details = asdict(features)
    details["imported_apis"] = sorted(features.imported_apis)
    print(json.dumps({"status": "OK", "sha256": hashlib.sha256(data).hexdigest(),
                      "threshold": REVIEW_THRESHOLD, **asdict(assessment),
                      "features": details}, ensure_ascii=True, indent=2))
    # Both risk verdicts are successful scans; 2 means no assessment available.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
