#!/usr/bin/env python3
"""MIT-0. Regression for protective cu68 metadata-aware rewrite gates.

Requires the M1 emit_fixture/verify_fixture tools and a native cu68+M2 Zip.
This is a fail-closed safety test, NOT Xtro production archive integration.
"""

from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from test_zip_interop import fixture, extras

ZIP = Path(os.environ.get("XTRO_ZIP_TEST_BINARY", "../zip30/zip")).resolve()
assert ZIP.is_file(), f"Zip binary missing: {ZIP}"


def invoke(*args, cwd):
    return subprocess.run(
        [str(ZIP), *map(str, args)],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def digest(p):
    return hashlib.sha256(p.read_bytes()).digest()


def has_xtro(z, name="owner.dat"):
    with zipfile.ZipFile(z) as archive:
        return [
            (tag, value)
            for tag, value in extras(archive.getinfo(name).extra)
            if tag in (0x5854, 0x4B46)
        ]


def check(encrypted: bool, root: Path):
    archive = fixture(encrypted, root)
    work = archive.parent
    original = archive.read_bytes()
    original_flds = has_xtro(archive)
    original_list = zipfile.ZipFile(archive).namelist()
    original_companion = original_list[1]
    owner = work / "owner.dat"
    owner.write_bytes(b"changed owner" * 200)
    now = time.time() + 180
    os.utime(owner, (now, now))
    # A replacement is now a supported metadata-aware operation: without
    # --xattrs, discard the old owner envelope and its stale companion,
    # leaving the original fixture untouched for subsequent guard tests.
    replacement = root / ("replacement-e.zip" if encrypted else "replacement-p.zip")
    shutil.copyfile(archive, replacement)
    r = invoke("-u", replacement, "owner.dat", cwd=work)
    assert (
        r.returncode == 0 and b"previous metadata discarded" in r.stdout + r.stderr
    ), r
    with zipfile.ZipFile(replacement) as rewritten:
        assert rewritten.namelist() == ["owner.dat"], rewritten.namelist()
        assert not [
            tag
            for tag, value in extras(rewritten.getinfo("owner.dat").extra)
            if tag == 0x5854 and value[:4] == b"XTRO"
        ]
        assert rewritten.read("owner.dat") == owner.read_bytes()
    assert archive.read_bytes() == original, "Fixture modified by independent update"
    # -FS, -DF and -F can remove/rewrite members without the usual UPDATE
    # path. Reject them until owner/companion graph rewrites are implemented.
    for bad_flags in (("-FS", "-r"), ("-DF", "-r"), ("-F",)):
        r = invoke(*bad_flags, archive, "owner.dat", cwd=work)
        assert r.returncode != 0 and archive.read_bytes() == original, (bad_flags, r)
    # A selected owner and its companion form one indivisible logical unit.
    # Automatic pair deletion and selected archive-copy are supported now.
    removed = root / ("removed-e.zip" if encrypted else "removed-p.zip")
    shutil.copyfile(archive, removed)
    r = invoke("-d", removed, "owner.dat", cwd=work)
    assert r.returncode == 0, r
    with zipfile.ZipFile(removed) as z:
        assert z.namelist() == [], z.namelist()
    assert archive.read_bytes() == original
    r = invoke("-d", archive, original_companion, cwd=work)
    assert r.returncode != 0 and archive.read_bytes() == original, r
    dest = root / ("partial-e.zip" if encrypted else "partial-p.zip")
    r = invoke(archive, "--copy", "owner.dat", "--out", dest, cwd=work)
    assert r.returncode == 0, r
    assert has_xtro(dest) == original_flds
    with zipfile.ZipFile(dest) as z:
        assert z.namelist() == original_list
        assert z.read(original_companion, pwd=b"test-password" if encrypted else None)
    dest.unlink()
    r = invoke(archive, "--copy", original_companion, "--out", dest, cwd=work)
    assert (
        r.returncode != 0 and not dest.exists() and archive.read_bytes() == original
    ), r
    # Adding an unrelated normal member must retain owner+companion associations.
    (work / "unrelated.txt").write_text("unrelated file content")
    r = invoke(archive, "unrelated.txt", cwd=work)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert has_xtro(archive) == original_flds
    with zipfile.ZipFile(archive) as z:
        assert z.namelist() == original_list + ["unrelated.txt"]
        assert z.read(original_companion, pwd=b"test-password" if encrypted else None)
        assert z.read("unrelated.txt") == b"unrelated file content"
    # A deletion of an unrelated member is permitted.
    r = invoke("-d", archive, "unrelated.txt", cwd=work)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert has_xtro(archive) == original_flds
    with zipfile.ZipFile(archive) as z:
        assert z.namelist() == original_list
    # Full unchanged archive copying must not strip per-owner metadata.
    dest = root / ("full-e.zip" if encrypted else "full-p.zip")
    r = invoke(archive, "--out", dest, cwd=work)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert has_xtro(dest) == original_flds
    with zipfile.ZipFile(dest) as z:
        assert z.namelist() == original_list
        assert z.read(original_companion, pwd=b"test-password" if encrypted else None)
    # Existing encrypted metadata remains untouched. Public Deflate metadata
    # can now undergo a complete ZipCrypto transition through ZipCloak.
    tools = ZIP.parent
    before = archive.read_bytes()
    if encrypted:
        r = subprocess.run(
            [str(tools / "zipcloak"), str(archive)],
            cwd=work,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=12,
        )
        assert r.returncode != 0 and b"all files encrypted" in r.stdout + r.stderr, r
    else:
        from test_zipcloak_xattrs import cloak

        target = work / "cloaked-pair.zip"
        rc, log = cloak(work, ["-O", str(target), str(archive)], 2)
        assert rc == 0, log[-400:]
        with zipfile.ZipFile(target) as z:
            owner, companion = z.infolist()
            assert owner.flag_bits & 1 and companion.flag_bits & 1
            assert companion.compress_type == zipfile.ZIP_DEFLATED
            assert z.read(companion, pwd=b"secret")[:-36] == zipfile.ZipFile(
                archive
            ).read(original_companion)
    assert archive.read_bytes() == before
    prior = set(work.glob("*.zip"))
    r = subprocess.run(
        [str(tools / "zipsplit"), "-n", "800000", str(archive)],
        cwd=work,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=12,
    )
    assert r.returncode == 0, r
    created = set(work.glob("*.zip")) - prior
    assert len(created) == 1, created
    with zipfile.ZipFile(next(iter(created))) as z:
        assert z.namelist() == original_list
        assert z.read(original_companion, pwd=b"test-password" if encrypted else None)
    assert archive.read_bytes() == before
    # Read-only zipnote should still list the archive unchanged.
    r = subprocess.run(
        [str(tools / "zipnote"), str(archive)],
        cwd=work,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=12,
    )
    assert r.returncode == 0 and b"owner.dat" in r.stdout, r
    edit = subprocess.run(
        [str(tools / "zipnote"), "-w", str(archive)],
        cwd=work,
        input=r.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=12,
    )
    assert edit.returncode == 0, edit
    assert has_xtro(archive) == original_flds
    with zipfile.ZipFile(archive) as z:
        assert z.namelist() == original_list
        assert z.read(original_companion, pwd=b"test-password" if encrypted else None)
    r = subprocess.run(
        [str(tools / "zipsplit"), "-t", "-n", "800000", str(archive)],
        cwd=work,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=12,
    )
    assert r.returncode == 0, r
    print(("encrypted" if encrypted else "public"), "archive guards passed")


def main():
    with tempfile.TemporaryDirectory(prefix="xtro-m2-guard-") as d:
        root = Path(d)
        check(False, root)
        check(True, root)
        # The temporary safety gates must not alter ordinary archives.
        normal = root / "ordinary.zip"
        (root / "ordinary.txt").write_text("ordinary test payload")
        r = invoke("-q", normal, "ordinary.txt", cwd=root)
        assert r.returncode == 0, r
        note = subprocess.run(
            [str(ZIP.parent / "zipnote"), str(normal)],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert note.returncode == 0, note
        r = subprocess.run(
            [str(ZIP.parent / "zipnote"), "-w", str(normal)],
            cwd=root,
            input=note.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert r.returncode == 0, r
        r = subprocess.run(
            [str(ZIP.parent / "zipsplit"), "-n", "800000", str(normal)],
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert r.returncode == 0, r
        print("Normal archive ZipNote/ZipSplit regression passed")
    print(
        "Archive update preservation, metadata-aware replacement, deletion, full copy passed"
    )


if __name__ == "__main__":
    main()
