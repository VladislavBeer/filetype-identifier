"""Identify file types from magic bytes and compare with the filename extension.

The program opens files in binary mode, reads only a small header, and does not execute them, open them in another program, nor modify them.

Note: This does not currently detect polyglots (files that are valid in two formats).
It reads only the start, so a polyglot with an MP3 header named .mp3 gets MATCH as an MP3.
"""
import argparse
from collections.abc import Callable
import os
import sys
from dataclasses import dataclass
from pathlib import Path

HEADER_BYTES = 4096


@dataclass(frozen=True)
class FileType:
    name: str
    extensions: frozenset
    patterns: tuple
    validator: Callable | None = None  # optional extra check on the header; True = accept


# ---------------------------------------------------------------------------
# Validators (second-stage checks) for signatures that are too short or too
# generic to trust on their own.
# ---------------------------------------------------------------------------

def _is_bmp(header: bytes) -> bool:
    # "BM" alone also starts plain text.
    if len(header) < 18:
        return False
    return int.from_bytes(header[14:18], "little") in {12, 40, 52, 56, 64, 108, 124}


def _is_pe(header: bytes) -> bool:
    if len(header) < 0x40:
        return False
    pe_offset = int.from_bytes(header[0x3C:0x40], "little")
    return header[pe_offset:pe_offset + 4] == b"PE\x00\x00"


def _is_mp3_frame(header: bytes) -> bool:
    # Raw MP3 frame header: 11 sync bits, then reject reserved field values.
    # Layer bits 00 are reserved, which also excludes AAC (ADTS) streams.
    if len(header) < 3:
        return False
    b1, b2 = header[1], header[2]
    return (
        (b1 & 0xE0) == 0xE0
        and ((b1 >> 3) & 0b11) != 0b01   # version 01 is reserved
        and ((b1 >> 1) & 0b11) != 0b00   # layer 00 is reserved
        and (b2 >> 4) != 0b1111          # bitrate index 1111 is invalid
        and ((b2 >> 2) & 0b11) != 0b11   # sample-rate index 11 is reserved
    )


def _ftyp_brand_in(*brands: bytes) -> Callable[[bytes], bool]:
    # ISO base media files (MP4, MOV, HEIC, AVIF) share "ftyp" at offset 4;
    # the 4-byte major brand at offset 8 tells them apart.
    def check(header: bytes) -> bool:
        return header[8:12] in brands
    return check

def _ebml_doctype(doctype: bytes) -> Callable[[bytes], bool]:
    # EBML DocType element: ID 0x42 0x82, a 1-byte size (0x80 | length), then the string.
    needle = b"\x42\x82" + bytes([0x80 | len(doctype)]) + doctype
    def check(header: bytes) -> bool:
        return needle in header[:64]   # DocType sits near the start of the EBML header
    return check


_ZIP_EXT = frozenset({".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt", ".ods", ".odp"})
_RAR_EXT = frozenset({".rar"})


SIGNATURES = (
    # --- images ---
    FileType("PNG", frozenset({".png"}), ((0, b"\x89PNG\r\n\x1a\n"),)),
    FileType("JPEG", frozenset({".jpg", ".jpeg"}), ((0, b"\xff\xd8\xff"),)),
    FileType("WEBP", frozenset({".webp"}), ((0, b"RIFF"), (8, b"WEBP"))),
    FileType("BMP", frozenset({".bmp", ".dib"}), ((0, b"BM"),), _is_bmp),
    FileType("HEIC", frozenset({".heic", ".heif"}), ((4, b"ftyp"),),_ftyp_brand_in(b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1")),

    FileType("GIF", frozenset({".gif"}), ((0, b"GIF87a"),)),
    FileType("GIF", frozenset({".gif"}), ((0, b"GIF89a"),)),
    FileType("AVIF", frozenset({".avif"}), ((4, b"ftyp"),), _ftyp_brand_in(b"avif", b"avis")),

    # --- documents ---
    FileType("PDF", frozenset({".pdf"}), ((0, b"%PDF-"),)),
    # OLE2 is the legacy Office container (also used by .msi, .msg, .pub, etc.).
    FileType("OLE2", frozenset({".doc", ".xls", ".ppt", ".dot", ".xlt", ".pot", ".msi", ".msg", ".vsd", ".pub", ".mpp"}),
             ((0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),)),

    # --- audio / video / multimedia ---
    FileType("WAV", frozenset({".wav", ".wave"}), ((0, b"RIFF"), (8, b"WAVE"))),
    FileType("AVI", frozenset({".avi"}), ((0, b"RIFF"), (8, b"AVI "))),
    FileType("MP3", frozenset({".mp3"}), ((0, b"ID3"),)),
    FileType("MP3", frozenset({".mp3"}), ((0, b"\xff"),), _is_mp3_frame),  # no ID3 tag: frame sync
    FileType("MOV", frozenset({".mov", ".qt"}), ((4, b"ftyp"),), _ftyp_brand_in(b"qt  ")),
    FileType("MP4", frozenset({".mp4", ".m4v", ".m4a", ".m4b", ".f4v"}), ((4, b"ftyp"),),
             _ftyp_brand_in(b"isom", b"iso2", b"mp41", b"mp42", b"avc1", b"dash",
                            b"M4A ", b"M4V ", b"M4B ", b"F4V ")),
    FileType("MKV", frozenset({".mkv", ".mka", ".mks", ".mk3d"}),((0, b"\x1a\x45\xdf\xa3"),), _ebml_doctype(b"matroska")),
    FileType("WebM", frozenset({".webm"}), ((0, b"\x1a\x45\xdf\xa3"),), _ebml_doctype(b"webm")),

    # --- archiving / compression ---
    # ZIP is also the container for Office files, JARs, APKs, etc.
    FileType("ZIP", _ZIP_EXT, ((0, b"PK\x03\x04"),)),
    FileType("ZIP", _ZIP_EXT, ((0, b"PK\x05\x06"),)),  # empty archive
    FileType("ZIP", _ZIP_EXT, ((0, b"PK\x07\x08"),)),  # spanned archive
    FileType("GZIP", frozenset({".gz", ".gzip", ".tgz"}), ((0, b"\x1f\x8b"),)),
    FileType("TAR", frozenset({".tar"}), ((257, b"ustar"),)),
    FileType("RAR", _RAR_EXT, ((0, b"Rar!\x1a\x07\x00"),)),        # RAR 1.5 - 4.x
    FileType("RAR", _RAR_EXT, ((0, b"Rar!\x1a\x07\x01\x00"),)),    # RAR 5.0+
    FileType("7-Zip", frozenset({".7z"}), ((0, b"7z\xbc\xaf'\x1c"),)),

    # --- databases ---
    FileType("SQLite", frozenset({".sqlite", ".sqlite3", ".db", ".db3"}), ((0, b"SQLite format 3\x00"),)),

    # --- executables ---
    FileType("Windows PE", frozenset({".exe", ".dll", ".sys", ".scr", ".ocx"}), ((0, b"MZ"),), _is_pe),
    FileType("Linux ELF", frozenset({".elf", ".so", ".o"}), ((0, b"\x7fELF"),)),
)

# Check the signatures that match the most bytes first, so specific matches
_ORDERED = tuple(sorted(SIGNATURES, key=lambda s: sum(len(magic) for _, magic in s.patterns), reverse=True))


def detect(header: bytes):
    # Return the matching FileType, or None.
    for sig in _ORDERED:
        if all(header[offset:offset + len(magic)] == magic for offset, magic in sig.patterns):
            if sig.validator is None or sig.validator(header):
                return sig
    return None


def check_file(path: Path):
    ext = path.suffix.lower()  # extension only: report.pdf.exe -> .exe
    try:
        with open(path, "rb") as f:
            header = f.read(HEADER_BYTES)
    except OSError as e:
        return "-", ext, f"ERROR ({e.strerror})"

    sig = detect(header)
    if sig is None:
        return "unknown", ext, "UNKNOWN_TYPE"
    if not ext:
        return sig.name, ext, "NO_EXTENSION"
    return sig.name, ext, "MATCH" if ext in sig.extensions else "MISMATCH"


def iter_files(targets, recursive):
    for t in targets:
        p = Path(t)
        if p.is_dir():
            if recursive:
                for root, _dirs, files in os.walk(p, followlinks=False):
                    for name in sorted(files):
                        yield Path(root) / name
            else:
                yield from sorted(x for x in p.iterdir() if x.is_file())
        else:
            yield p


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+", help="files or directories")
    ap.add_argument("-r", "--recursive", action="store_true")
    args = ap.parse_args(argv)

    counts = {}
    for path in iter_files(args.paths, args.recursive):
        if path.is_symlink():
            continue
        detected, ext, verdict = check_file(path)
        key = verdict.split(" ")[0]
        counts[key] = counts.get(key, 0) + 1
        print(f"{verdict:<13} {detected:<11} {ext or '(none)':<8} {path}")

    print("\n" + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 1 if counts.get("MISMATCH") else 0


if __name__ == "__main__":
    sys.exit(main())