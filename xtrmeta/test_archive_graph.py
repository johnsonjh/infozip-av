#!/usr/bin/env python3
"""MIT-0. Real production Zip tests of malformed Xtro archive graphs.

Do not use the ZIP parser as the metadata payload verifier. Tests are for
central-directory association preflight and transactional nonpublication.
"""

from __future__ import annotations
import io
import pathlib
import shutil
import struct
import calendar
import subprocess
import tempfile
import zipfile
from test_zip_interop import fixture

ZIP = pathlib.Path("../zip30/zip").resolve()
COMPANION = "__XTRO_ZIP__/x/0102030405060708090a0b0c0d0e0f10.xtm"


def rewrite(src, dest, callback):
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dest, "w") as zout:
        for info in zin.infolist():
            if info.filename != COMPANION:
                content = zin.read(info)
                for name, extra in callback(info.filename, info.extra):
                    out = zipfile.ZipInfo(name, date_time=info.date_time)
                    out.compress_type = info.compress_type
                    out.extra = extra
                    zout.writestr(out, content)
            else:
                content = zin.read(info)
                for name, extra in callback(info.filename, info.extra):
                    out = zipfile.ZipInfo(name, date_time=info.date_time)
                    out.compress_type = info.compress_type
                    out.extra = extra
                    zout.writestr(out, content)


def edit_central_date(raw, filename, dosdate):
    """Alter only the central ZIP date for controlled selection tests."""
    b = bytearray(raw)
    e = b.rfind(b"PK\x05\x06")
    assert e >= 0
    count, off = (
        struct.unpack_from("<HI", b, e + 10)[0],
        struct.unpack_from("<I", b, e + 16)[0],
    )
    for _ in range(count):
        assert b[off : off + 4] == b"PK\x01\x02"
        nl, el, cl = struct.unpack_from("<HHH", b, off + 28)
        name = bytes(b[off + 46 : off + 46 + nl]).decode("ascii")
        if name == filename:
            struct.pack_into("<H", b, off + 14, dosdate)
            # Zip prefers extended UT mtime over the DOS central timestamp.
            # Change both to exercise date filtering rather than just display.
            epos = off + 46 + nl
            end = epos + el
            year = 1980 + ((dosdate >> 9) & 127)
            month = (dosdate >> 5) & 15
            day = dosdate & 31
            stamp = calendar.timegm((year, month, day, 0, 0, 0))
            while epos < end:
                tag, ln = struct.unpack_from("<HH", b, epos)
                assert epos + 4 + ln <= end
                if tag == 0x5455 and ln >= 5 and (b[epos + 4] & 1):
                    struct.pack_into("<I", b, epos + 5, stamp)
                epos += 4 + ln
        off += 46 + nl + el + cl
    return bytes(b)


def dosdate(y, m, d):
    return ((y - 1980) << 9) | (m << 5) | d


def check_date_filter(src, root):
    original = src.read_bytes()
    for old in ("owner.dat", COMPANION):
        dst = root / ("date-" + ("owner" if old == "owner.dat" else "side") + ".zip")
        b = edit_central_date(original, old, dosdate(2020, 1, 1))
        other = COMPANION if old == "owner.dat" else "owner.dat"
        b = edit_central_date(b, other, dosdate(2026, 10, 15))
        dst.write_bytes(b)
        before = dst.read_bytes()
        q = subprocess.run(
            [str(ZIP), "-d", str(dst), "*", "-t", "2022-01-01"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert q.returncode != 0 and b"Xtro" in q.stdout + q.stderr, (old, q)
        assert dst.read_bytes() == before, old
        out = root / (
            "date-copy-" + ("owner" if old == "owner.dat" else "side") + ".zip"
        )
        q = subprocess.run(
            [str(ZIP), str(dst), "--copy", "*", "-t", "2022-01-01", "--out", str(out)],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert q.returncode != 0 and b"Xtro" in q.stdout + q.stderr, (old, q)
        assert not out.exists() and dst.read_bytes() == before, old


def change_local_owner(raw):
    """Change one byte of LOCAL owner ID without modifying CENTRAL owner."""
    b = bytearray(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        off = z.getinfo("owner.dat").header_offset
    assert b[off : off + 4] == b"PK\x03\x04"
    nl, el = struct.unpack_from("<HH", b, off + 26)
    pos = off + 30 + nl
    end = pos + el
    while pos < end:
        tag, n = struct.unpack_from("<HH", b, pos)
        assert pos + 4 + n <= end
        if tag == 0x5854 and b[pos + 4 : pos + 8] == b"XTRO":
            assert n == 40
            b[pos + 12] ^= 0x10
            return bytes(b)
        pos += 4 + n
    raise AssertionError("no local Xtro header")


def check_reject(src, cwd, label):
    before = src.read_bytes()
    (cwd / "unrelated.txt").write_bytes(b"unrelated" * 20)
    p = subprocess.run(
        [str(ZIP), str(src), "unrelated.txt"],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert p.returncode != 0, (label, p.stdout, p.stderr)
    assert src.read_bytes() == before, (label, "modified source")
    assert b"Xtro" in p.stdout + p.stderr, (label, p.stdout, p.stderr)


def tweak_version(extra):
    i = extra.index(b"XTRO")
    return extra[: i + 4] + b"\x02" + extra[i + 5 :]


def tweak_mode(extra):
    i = extra.index(b"XTRO")
    return extra[: i + 6] + b"\x03" + extra[i + 7 :]


def duplicate_xtro(extra):
    i = extra.index(b"XTRO") - 4
    n = int.from_bytes(extra[i + 2 : i + 4], "little")
    return extra + extra[i : i + 4 + n]


def main():
    with tempfile.TemporaryDirectory(prefix="xtro-graph-") as tmp:
        root = pathlib.Path(tmp)
        reference = fixture(False, root)
        check_date_filter(reference, root)
        mismatch = root / "mismatched-local.zip"
        mismatch.write_bytes(change_local_owner(reference.read_bytes()))
        check_reject(mismatch, root, "local versus central owner mismatch")
        tests = {
            "owner_missing_companion": lambda name, field: (
                [] if name == COMPANION else [(name, field)]
            ),
            "companion_without_owner": lambda name, field: (
                [] if name == "owner.dat" else [(name, field)]
            ),
            "duplicate_owner_id": lambda name, field: (
                [(name, field), ("duplicate-owner.dat", field)]
                if name == "owner.dat"
                else [(name, field)]
            ),
            "duplicate_companion": lambda name, field: (
                [(name, field), (name, field)] if name == COMPANION else [(name, field)]
            ),
            "malformed_reserved_name": lambda name, field: (
                [("bad-name/" + name, field)] if name == COMPANION else [(name, field)]
            ),
            "companion_only_modified_name": lambda name, field: (
                [(name.upper(), field)] if name == COMPANION else [(name, field)]
            ),
            "invalid_central_version": lambda name, field: (
                [(name, tweak_version(field))]
                if name == "owner.dat"
                else [(name, field)]
            ),
            "invalid_mode": lambda name, field: (
                [(name, tweak_mode(field))] if name == "owner.dat" else [(name, field)]
            ),
            "duplicated_xtro_field": lambda name, field: (
                [(name, duplicate_xtro(field))]
                if name == "owner.dat"
                else [(name, field)]
            ),
        }
        for label, change in tests.items():
            path = root / (label + ".zip")
            rewrite(reference, path, change)
            check_reject(path, root, label)
        # A normal ZIP may contain arbitrary files under a visually similar
        # directory: only the exact reserved form becomes a sidecar.
        benign = root / "benign.zip"
        with zipfile.ZipFile(benign, "w") as f:
            f.writestr("__XTRO_ZIP__/unrelated.txt", b"data")
        q = subprocess.run(
            [str(ZIP), str(benign), "unrelated.txt"],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert q.returncode == 0, (q.stdout, q.stderr)
        # The exact companion-shaped reserved pathname is never allowed
        # without a matching owner, even when all other fields are absent.
        orphan = root / "orphan.zip"
        with zipfile.ZipFile(orphan, "w") as f:
            f.writestr(COMPANION, b"data")
        check_reject(orphan, root, "standalone orphan")
    print(
        "Xtro graph rejection: 10 malformed/reserved, 4 date-filter, 1 local/central mismatch cases passed"
    )


if __name__ == "__main__":
    main()
