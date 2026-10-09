#!/usr/bin/env python3
"""RefPtr 0x9903 advisory diagnostics and content-integrity regression tests.

The writer supplies a fresh fixture; all corruptions are local to this suite.
Run after building zipdedup, zip and unzip. No proprietary WinZip fixture is
needed, but independent WinZip vectors are tested by test-refptr9903.
"""

import hashlib
import pathlib
import struct
import subprocess
import tempfile
import zipfile
import zlib

from test_zipdedup import ROOT, TOOL, UNZIP, make_test_zip, run


def entry_offsets(blob):
    # Archive is intentionally ordinary single-disk ZIP, without ZIP64.
    z = zipfile.ZipFile(__import__("io").BytesIO(blob))
    offsets = {}
    pos = z.start_dir
    for e in z.infolist():
        assert blob[pos : pos + 4] == b"PK\x01\x02"
        nl, xl, cl = struct.unpack_from("<HHH", blob, pos + 28)
        assert blob[pos + 46 : pos + 46 + nl] == e.filename.encode("ascii")
        ef = pos + 46 + nl
        extras = blob[ef : ef + xl]
        fld = extras.find(b"\x03\x99\x14\x00")
        offsets[e.filename] = (pos, ef, ef + fld if fld != -1 else None, e)
        pos += 46 + nl + xl + cl
    z.close()
    return offsets


def crc9903(blob, central, uuid):
    method = struct.unpack_from("<H", blob, central + 10)[0]
    dostime, dosdate = struct.unpack_from("<HH", blob, central + 12)
    crc = struct.unpack_from("<I", blob, central + 16)[0]
    return zlib.crc32(struct.pack("<IHHI", method, dostime, dosdate, crc) + uuid)


def check(
    unzipfile,
    blob,
    name,
    mutation,
    expected_rc,
    text=None,
    selected=None,
    expect_contents=False,
):
    mutated = bytearray(blob)
    offsets = entry_offsets(blob)
    mutation(mutated, offsets)
    path = unzipfile.parent / name
    path.write_bytes(mutated)
    args = [str(UNZIP), "-tq", str(path)]
    if selected:
        args.append(selected)
    completed = subprocess.run(args, capture_output=True, text=True)
    both = completed.stdout + completed.stderr
    assert completed.returncode == expected_rc, (name, completed.returncode, both)
    if text is not None:
        assert text in both, (name, text, both)
    if expected_rc == 0:
        assert "warning: RefPtr" not in both, (name, both)
    if expect_contents:
        member = selected or "dup-deflate.bin"
        p = subprocess.run([str(UNZIP), "-p", str(path), member], capture_output=True)
        assert p.returncode == expected_rc, (name, p.returncode, p.stderr)
        with zipfile.ZipFile(unzipfile) as reference:
            expected = reference.read("source.bin")
        assert p.stdout == expected, (name, len(p.stdout), len(expected))
    return path


def field(buf, offsets, name):
    pos, ef, meta, info = offsets[name]
    assert meta is not None
    return pos, meta, info


def remove_field(which):
    def alter(buf, offsets):
        _, meta, _ = field(buf, offsets, which)
        buf[meta : meta + 2] = b"\xff\xaa"

    return alter


def bad_crc(which):
    def alter(buf, offsets):
        _, meta, _ = field(buf, offsets, which)
        buf[meta + 4 : meta + 8] = b"\0" * 4

    return alter


def bad_size(buf, offsets):
    # Keep the overall extra-field layout valid.  Turn the existing 5-byte
    # 0x000a record into a malformed one-byte 0x9903 and rename the former
    # valid 0x9903 record; the RefPtr validator, not do_string(), must warn.
    _, ef, meta, _ = offsets["dup-deflate.bin"]
    assert meta is not None and buf[ef : ef + 4] == b"\x0a\x00\x01\x00"
    buf[ef : ef + 2] = b"\x03\x99"
    buf[meta : meta + 2] = b"\xff\xaa"


def flip_uuid(which, fix_crc):
    def alter(buf, offsets):
        central, meta, _ = field(buf, offsets, which)
        buf[meta + 23] ^= 1
        if fix_crc:
            uuid = buf[meta + 8 : meta + 24]
            struct.pack_into("<I", buf, meta + 4, crc9903(buf, central, uuid))

    return alter


def all_uuid(buf, offsets):
    for name in ("source.bin", "dup-deflate.bin", "dup-store.bin"):
        flip_uuid(name, True)(buf, offsets)


def duplicate_field(buf, offsets):
    central, meta, _ = field(buf, offsets, "dup-deflate.bin")
    _, ef, _, _ = offsets["dup-deflate.bin"]
    el = struct.unpack_from("<H", buf, central + 30)[0]
    end = ef + el
    buf[end:end] = buf[meta : meta + 24]
    struct.pack_into("<H", buf, central + 30, el + 24)
    eocd = buf.rfind(b"PK\x05\x06")
    assert eocd >= 0
    cd_size = struct.unpack_from("<I", buf, eocd + 12)[0]
    struct.pack_into("<I", buf, eocd + 12, cd_size + 24)


def wrong_digest(buf, offsets):
    _, _, _, info = offsets["dup-deflate.bin"]
    local = info.header_offset
    nl, el = struct.unpack_from("<HH", buf, local + 26)
    assert struct.unpack_from("<H", buf, local + 8)[0] == 92
    buf[local + 30 + nl + el] ^= 1


def main():
    assert TOOL.exists() and UNZIP.exists()
    with tempfile.TemporaryDirectory(prefix="refptr-metadata-") as temp:
        d = pathlib.Path(temp)
        original = d / "original.zip"
        valid = d / "valid.zip"
        make_test_zip(original)
        run(TOOL, original, valid)
        blob = valid.read_bytes()
        with zipfile.ZipFile(valid) as z:
            assert z.getinfo("dup-deflate.bin").compress_type == 92
            assert z.getinfo("source.bin").compress_type == 0
        run(UNZIP, "-tq", valid)
        # Selection must not trigger warnings from another, unselected member.
        check(
            valid,
            blob,
            "missing-reference.zip",
            remove_field("dup-deflate.bin"),
            1,
            "reference missing central 0x9903",
            expect_contents=True,
        )
        check(
            valid,
            blob,
            "missing-source.zip",
            remove_field("source.bin"),
            1,
            "physical source missing central 0x9903",
        )

        def missing_both(buf, offsets):
            for part in ("source.bin", "dup-deflate.bin", "dup-store.bin"):
                remove_field(part)(buf, offsets)

        check(
            valid,
            blob,
            "missing-both.zip",
            missing_both,
            1,
            "reference missing central 0x9903",
            expect_contents=True,
        )
        check(
            valid,
            blob,
            "wrong-ref-crc.zip",
            bad_crc("dup-deflate.bin"),
            1,
            "reference 0x9903 CRC mismatch",
            expect_contents=True,
        )
        check(
            valid,
            blob,
            "wrong-source-crc.zip",
            bad_crc("source.bin"),
            1,
            "physical source 0x9903 CRC mismatch",
        )
        check(
            valid, blob, "bad-field-size.zip", bad_size, 1, "reference malformed 0x9903"
        )

        # Do not relax the existing generic ZIP-extra structural validator:
        # claiming a 19-byte payload within an unchanged 20-byte field leaves
        # an invalid orphan byte and must still be a hard ZIP parse error.
        def broken_extra_layout(buf, offsets):
            _, meta, _ = field(buf, offsets, "dup-deflate.bin")
            struct.pack_into("<H", buf, meta + 2, 19)

        check(
            valid,
            blob,
            "bad-extra-structure.zip",
            broken_extra_layout,
            2,
            "malformed extra field structure",
        )
        check(
            valid,
            blob,
            "duplicate-field.zip",
            duplicate_field,
            1,
            "reference duplicate 0x9903",
        )
        check(
            valid,
            blob,
            "invalid-uuid.zip",
            flip_uuid("dup-deflate.bin", False),
            1,
            "reference 0x9903 CRC mismatch",
        )
        check(
            valid,
            blob,
            "crc-valid-mismatching-uuid.zip",
            flip_uuid("dup-deflate.bin", True),
            1,
            "source/reference UUID mismatch",
            expect_contents=True,
        )
        check(
            valid,
            blob,
            "crc-valid-modified-uuid.zip",
            all_uuid,
            0,
            expect_contents=True,
        )
        bad_sha = check(
            valid,
            blob,
            "bad-sha1.zip",
            wrong_digest,
            2,
            "source missing, invalid, or digest mismatch",
        )
        # Regression: a failed RefPtr decode must not become success when
        # close_outfile() resets the member's return code (normal extraction).
        extract_dir = d / "extracted-invalid"
        extract_dir.mkdir()
        result = subprocess.run(
            [str(UNZIP), "-oq", str(bad_sha), "-d", str(extract_dir)],
            capture_output=True,
        )
        assert result.returncode >= 2, (result.returncode, result.stdout, result.stderr)
        crc_warn = d / "wrong-ref-crc.zip"
        verified_dir = d / "extracted-valid-with-warning"
        verified_dir.mkdir()
        result = subprocess.run(
            [str(UNZIP), "-oq", str(crc_warn), "-d", str(verified_dir)],
            capture_output=True,
        )
        assert result.returncode == 1, (result.returncode, result.stderr)
        with zipfile.ZipFile(valid) as z:
            assert (verified_dir / "dup-deflate.bin").read_bytes() == z.read(
                "source.bin"
            )
        path = check(
            valid,
            blob,
            "bad-other-ref.zip",
            bad_crc("dup-deflate.bin"),
            0,
            selected="tiny-1",
        )
        result = subprocess.run(
            [str(UNZIP), "-p", str(path), "tiny-1"], capture_output=True
        )
        assert result.returncode == 0 and result.stdout == b"x"
        # Warn for selected reference even when quiet, and keep binary output
        # completely separate from the diagnostics.
        result = subprocess.run(
            [str(UNZIP), "-p", str(path), "dup-deflate.bin"], capture_output=True
        )
        assert result.returncode == 1 and b"warning: RefPtr" in result.stderr
        assert b"warning: RefPtr" not in result.stdout
        with zipfile.ZipFile(valid) as z:
            assert result.stdout == z.read("source.bin")
    print("PASS: RefPtr 0x9903 absent/invalid/duplicate/UUID mismatches")
    print("PASS: intact output, fatal SHA-1 in normal extraction, status preserved")
    print("PASS: selective extraction, quiet warnings and clean stdout")


if __name__ == "__main__":
    main()
