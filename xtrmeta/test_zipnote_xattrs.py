#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""M6C: ZipNote owner renames and comments preserve Xtro metadata identities."""

import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIP = ROOT / "zip30/zip"
NOTE = pathlib.Path(
    os.environ.get("XTRO_ZIPNOTE_TEST_BINARY", str(ROOT / "zip30/zipnote"))
)
UNZIP = ROOT / "unzip60/unzip"
checks = 0


def check(test, explanation):
    global checks
    checks += 1
    if not test:
        raise AssertionError(explanation)


def run(*argv, cwd=None, input=None, expect=0):
    p = subprocess.run(
        [str(a) for a in argv],
        cwd=cwd,
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
    )
    if expect == 0:
        check(
            p.returncode == 0,
            "%r returned %s: %r" % (argv, p.returncode, p.stderr[-1200:]),
        )
    else:
        check(p.returncode != 0, "%r unexpectedly succeeded" % (argv,))
    return p


def fields(payload):
    at = 0
    while at < len(payload):
        check(len(payload) - at >= 4, "complete extra header")
        kind, n = struct.unpack_from("<HH", payload, at)
        at += 4
        check(n <= len(payload) - at, "complete extra body")
        yield kind, payload[at : at + n]
        at += n


def owner_fields(archive):
    with zipfile.ZipFile(archive) as z:
        return {
            e.filename: [
                (kind, value)
                for kind, value in fields(e.extra)
                if kind in (0x5854, 0x4B46, 0x9901)
            ]
            for e in z.infolist()
        }


def note_edit(archive, changes=None, comment=None, entry_comment=None):
    changes = changes or {}
    original = run(NOTE, archive).stdout.decode("latin1")
    text = original
    for old, new in changes.items():
        mark = "@ " + old + "\n"
        check(mark in text, "requested ZipNote owner exists")
        text = text.replace(mark, mark + "@=" + new + "\n", 1)
        if entry_comment is not None:
            text = text.replace(
                mark + "@=" + new + "\n",
                mark + "@=" + new + "\n" + entry_comment + "\n",
                1,
            )
    if comment is not None:
        text = text.replace(
            "@ (zip file comment below this line)\n",
            "@ (zip file comment below this line)\n" + comment + "\n",
            1,
        )
    return text.encode("latin1")


def unchanged_archive_on_error(archive, source):
    before = archive.read_bytes()
    p = run(NOTE, "-w", archive, input=source, expect=1)
    check(archive.read_bytes() == before, "failed edit leaves original bytes unchanged")
    check(
        b"Xtro" in p.stderr or b"Xtro" in p.stdout, "Xtro-specific rejection reported"
    )


def roundtrip(
    directory, mode, large, ae1=False, fwkcs=False, forcezip64=False, store=False
):
    d = directory / (
        mode
        + ("-large" if large else "-inline")
        + ("-md5" if fwkcs else "")
        + ("-zip64" if forcezip64 else "")
        + ("-store" if store else "")
    )
    d.mkdir()
    payload = b"AE2 input" if mode == "ae2" else b"\x00\xffmetadata test\x01\n" * 111
    owner = d / "owner.bin"
    owner.write_bytes(payload)
    attrs = {b"user.note": b"abc\x00\xff"}
    if large:
        attrs[b"user.extra1"] = b"M" * 36000
        attrs[b"user.extra2"] = b"N" * 36000
    for name, value in attrs.items():
        os.setxattr(owner, name, value)
    archive = d / "archive.zip"
    args = [ZIP, "--xattrs"]
    if fwkcs:
        args += ["--fwkcs-md5"]
    if forcezip64:
        args += ["-fz"]
    if store:
        args += ["-0"]
    if mode == "zipcrypto":
        args += ["-P", "test-password"]
    elif mode.startswith("ae"):
        args += ["--aes-strength", "256", "-eP", "test-password"]
        if mode == "ae3":
            args += ["--aes-mode", "quantum"]
    run(*(args + [archive, owner.name]), cwd=d)
    with zipfile.ZipFile(archive) as z:
        srcnames = z.namelist()
        check(srcnames[0] == owner.name, "owner first")
        companion = next((s for s in srcnames if s.startswith("__XTRO_ZIP__/")), None)
        check(bool(companion) == (large or mode != "plain"), "companion transport")
        original_meta = owner_fields(archive)
        original_comment = z.comment
    raw = note_edit(
        archive,
        {owner.name: "renamed.bin"},
        "zipnote M6C archive comment",
        "entry comment after rename",
    )
    run(NOTE, "-w", archive, input=raw)
    with zipfile.ZipFile(archive) as z:
        check(z.comment == b"zipnote M6C archive comment", "archive comment survived")
        check("owner.bin" not in z.namelist(), "old name removed")
        check("renamed.bin" in z.namelist(), "new name visible")
        check(
            z.getinfo("renamed.bin").file_size == len(payload), "file length unchanged"
        )
        check(
            z.getinfo("renamed.bin").comment == b"entry comment after rename",
            "owner entry comment",
        )
        if mode.startswith("ae"):
            v = [
                value
                for tag, value in fields(z.getinfo("renamed.bin").extra)
                if tag == 0x9901
            ]
            check(len(v) == 1, "AES owner remains AES")
            version = struct.unpack_from("<H", v[0])[0]
            check(
                version == (3 if mode == "ae3" else 1 if ae1 else 2),
                "AES vendor version retained",
            )
        check(
            set(z.namelist()) == (set(srcnames) - {"owner.bin"}) | {"renamed.bin"},
            "no missing/extra companion",
        )
    later_meta = owner_fields(archive)
    check(
        later_meta.pop("renamed.bin") == original_meta.pop("owner.bin"),
        "owner Xtro, FWKCS and AES central fields untouched",
    )
    check(later_meta == original_meta, "companion metadata untouched")
    # A second rewrite changing only comments must preserve the relationship.
    first_meta = owner_fields(archive)
    run(NOTE, "-w", archive, input=note_edit(archive, comment="second edit"))
    check(
        owner_fields(archive) == first_meta,
        "metadata fields byte-identical after second rewrite",
    )
    output = d / "restored"
    output.mkdir()
    unzip_cmd = [UNZIP, "-o", "--xattrs"]
    if mode != "plain":
        unzip_cmd += ["-P", "test-password"]
    run(*(unzip_cmd + [archive, "-d", output]))
    restored = output / "renamed.bin"
    check(restored.read_bytes() == payload, "renamed content correct")
    check(
        {os.fsencode(k): os.getxattr(restored, k) for k in os.listxattr(restored)}
        == attrs,
        "renamed attributes exactly restored",
    )
    check(not (output / "__XTRO_ZIP__").exists(), "no internal files extracted")
    # No user-provided rename may modify the internal namespace.
    if companion:
        unchanged_archive_on_error(
            archive, note_edit(archive, {companion: "other.xtm"})
        )
    unchanged_archive_on_error(
        archive,
        note_edit(archive, {"renamed.bin": "__XTRO_ZIP__/x/not-a-companion.xtm"}),
    )
    # A wrong local reference must never pass a comment-only rewrite even
    # when the central graph is otherwise complete. Native Zip copy checks
    # local/central identity before it writes the replacement archive.
    with zipfile.ZipFile(archive) as z:
        e = z.getinfo("renamed.bin")
    damaged = bytearray(archive.read_bytes())
    off = e.header_offset
    check(damaged[off : off + 4] == b"PK\x03\x04", "local entry signature")
    nl, el = struct.unpack_from("<HH", damaged, off + 26)
    at = off + 30 + nl
    end = at + el
    found = False
    while at < end:
        tag, length = struct.unpack_from("<HH", damaged, at)
        check(at + 4 + length <= end, "local extra bounds")
        if tag == 0x5854 and damaged[at + 4 : at + 8] == b"XTRO":
            damaged[at + 4 + 8] ^= 1
            found = True
            break
        at += 4 + length
    check(found, "local Xtro field for mismatch test")
    badlocal = d / "badlocal.zip"
    badlocal.write_bytes(damaged)
    unchanged_archive_on_error(badlocal, note_edit(badlocal, comment="nope"))
    # Simulate stale or malformed graph: old owner is removed by a foreign ZIP
    # library while preserving companion as an ordinary member.
    if companion:
        malformed = d / "orphan.zip"
        with zipfile.ZipFile(archive) as z, zipfile.ZipFile(malformed, "w") as out:
            for e in z.infolist():
                if e.filename == "renamed.bin":
                    continue
                # Copy this raw ordinary member for public payloads only.
                if mode != "plain":
                    break
                out.writestr(e, z.read(e))
        if mode == "plain":
            unchanged_archive_on_error(malformed, note_edit(malformed, comment="nope"))
    return original_comment


def two_owner_roundtrip(root):
    d = root / "two-owners"
    d.mkdir()
    names = ("first.bin", "second.bin")
    content = b"identical contents for distinct identities" * 100
    expected = {}
    for i, name in enumerate(names):
        source = d / name
        source.write_bytes(content)
        attrs = {b"user.identity": (b"owner" + str(i).encode("ascii"))}
        if i == 1:
            attrs[b"user.large1"] = b"A" * 36000
            attrs[b"user.large2"] = b"B" * 36000
        for key, value in attrs.items():
            os.setxattr(source, key, value)
        expected[name] = attrs
    archive = d / "two.zip"
    run(ZIP, "--xattrs", archive, *names, cwd=d)
    before = owner_fields(archive)
    run(
        NOTE,
        "-w",
        archive,
        input=note_edit(
            archive, {"first.bin": "moved.bin"}, "two distinct attribute identities"
        ),
    )
    after = owner_fields(archive)
    check(
        after.pop("moved.bin") == before.pop("first.bin"),
        "renamed owner retains original identity",
    )
    check(after == before, "unrenamed owner and companion unchanged")
    with zipfile.ZipFile(archive) as z:
        check(
            len([e for e in z.infolist() if e.filename.startswith("__XTRO_ZIP__/")])
            == 1,
            "exactly one companion in two-owner archive",
        )
    out = d / "out"
    out.mkdir()
    run(UNZIP, "-o", "--xattrs", archive, "-d", out)
    expected["moved.bin"] = expected.pop("first.bin")
    for name, attrs in expected.items():
        item = out / name
        check(item.read_bytes() == content, "separate owner content")
        check(
            {os.fsencode(k): os.getxattr(item, k) for k in os.listxattr(item)} == attrs,
            "separate owner xattrs do not cross-contaminate",
        )
    check(not (out / "__XTRO_ZIP__").exists(), "no extracted internal companions")


def main():
    base = "/dev/shm" if pathlib.Path("/dev/shm").is_dir() else None
    with tempfile.TemporaryDirectory(prefix="xtro-m6c-note-", dir=base) as td:
        root = pathlib.Path(td)
        for mode in ("plain", "zipcrypto", "ae1", "ae2", "ae3"):
            for large in (False, True):
                roundtrip(root, mode, large, ae1=(mode == "ae1"))
        roundtrip(root, "plain", True, fwkcs=True)
        roundtrip(root, "plain", True, forcezip64=True)
        roundtrip(root, "plain", True, store=True)
        roundtrip(root, "zipcrypto", True, store=True)
        two_owner_roundtrip(root)
        # No Xtro archive retains its established ZipNote editing behavior.
        normal = root / "normal.zip"
        (root / "plain.txt").write_text("ordinary")
        run(ZIP, normal, "plain.txt", cwd=root)
        run(NOTE, "-w", normal, input=note_edit(normal, {"plain.txt": "changed.txt"}))
        with zipfile.ZipFile(normal) as z:
            check(z.namelist() == ["changed.txt"], "non-Xtro filename rename")
    print("M6C ZipNote rename/comment round trips: %d checks, 0 failures" % checks)


if __name__ == "__main__":
    main()
