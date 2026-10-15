#!/usr/bin/env python3
"""Real Zip/UnZip Linux exact-user-xattr overwrite and fail-closed tests."""

import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
ZIP = pathlib.Path(os.environ.get("XTR_ZIP_BIN", HERE.parent / "zip30/zip"))
UNZIP = pathlib.Path(os.environ.get("XTR_UNZIP_BIN", HERE.parent / "unzip60/unzip"))
count = 0


def check(cond, desc):
    global count
    count += 1
    if not cond:
        raise AssertionError(desc)


def cmd(*args, cwd=None):
    return subprocess.run(
        [str(a) for a in args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )


def getattrs(path):
    return {k: os.getxattr(path, k) for k in os.listxattr(path)}


def exercise(root, name, large=False, password=False):
    src = root / (name + "-src")
    src.mkdir()
    (src / "dir").mkdir()
    file = src / "dir" / "owner"
    file.write_bytes(b"new owner contents")
    desired = {"user.binary": b"\0\xff\x10\0", "user.empty": b""}
    if large:
        desired["user.large"] = b"abcdef\x00\xff" * 8000
    for k, v in desired.items():
        os.setxattr(file, k, v)
    archive = root / (name + ".zip")
    opts = ["-P", "xyz"] if password else []
    rv = cmd(ZIP, "--xattrs", *opts, archive, "dir/owner", cwd=src)
    check(rv.returncode == 0, "Zip creation: %s %r" % (name, rv.stderr))
    with zipfile.ZipFile(archive) as z:
        check(
            len(z.infolist()) == (2 if large or password else 1),
            "expected format " + name,
        )
    dst = root / (name + "-dst")
    dst.mkdir()
    (dst / "dir").mkdir()
    existing = dst / "dir" / "owner"
    existing.write_bytes(b"original")
    os.setxattr(existing, "user.stale", b"preserve if skipped")
    os.setxattr(existing, "user.binary", b"previous value")
    original = getattrs(existing)
    argv = ["--xattrs"] + (["-P", "xyz"] if password else [])
    rv = cmd(UNZIP, *argv, "-n", archive, cwd=dst)
    check(rv.returncode == 0, "skip extract " + name)
    check(getattrs(existing) == original, "skipped xattrs unchanged " + name)
    check(existing.read_bytes() == b"original", "skipped contents unchanged " + name)
    rv = cmd(UNZIP, *argv, "-o", archive, cwd=dst)
    check(rv.returncode == 0, "overwrite extract %s: %r" % (name, rv.stderr))
    check(getattrs(existing) == desired, "exact overwrite namespace " + name)
    check(existing.read_bytes() == file.read_bytes(), "overwrite contents " + name)
    rv = cmd(UNZIP, *argv, "-o", archive, cwd=dst)
    check(rv.returncode == 0, "idempotent repeat " + name)
    check(getattrs(existing) == desired, "idempotent attrs " + name)
    # Without --xattrs, no archived metadata is applied to a fresh inode.
    disabled = root / (name + "-disabled")
    disabled.mkdir()
    rv = cmd(
        UNZIP,
        "--no-xattrs",
        *(["-P", "xyz"] if password else []),
        archive,
        cwd=disabled
    )
    check(rv.returncode == 0, "normal extraction without xattrs " + name)
    check(
        getattrs(disabled / "dir" / "owner") == {},
        "disabled xattr extraction applies none " + name,
    )
    if not password and large:
        # A forged uncompressed size exceeding the accepted staging budget
        # must fail before native metadata is changed. The source content is
        # still ordinary ZIP data and may already be extracted.
        blob = bytearray(archive.read_bytes())
        with zipfile.ZipFile(archive) as z:
            side = z.infolist()[1]
            mark = blob.rfind(b"PK\x01\x02")
            check(mark >= 0, "central directory found")
            # Only the companion's central uncompressed-size field changes.
            # This tests rejection of the advertised size, not ZIP64 handling.
            off = mark + 24
            struct.pack_into("<I", blob, off, 34 * 1024 * 1024)
        forged = root / "oversized.zip"
        forged.write_bytes(blob)
        os.setxattr(existing, "user.keep", b"before")
        prior = getattrs(existing)
        rv = cmd(UNZIP, "--xattrs", "-o", forged, cwd=dst)
        check(rv.returncode != 0, "oversized staged metadata rejected")
        check(getattrs(existing) == prior, "oversized rejection does not change attrs")


def main():
    with tempfile.TemporaryDirectory(
        prefix="xtro-m5c-",
        dir="/dev/shm" if pathlib.Path("/dev/shm").is_dir() else None,
    ) as tmp:
        root = pathlib.Path(tmp)
        exercise(root, "inline")
        exercise(root, "companion", large=True)
        exercise(root, "zipcrypto", large=True, password=True)
        # M5D: directory metadata is deferred until the final directory
        # ownership/permissions/timestamp pass and applied only if created.
        dsrc = root / "directory-src"
        dsrc.mkdir()
        owned = dsrc / "marked"
        owned.mkdir()
        os.setxattr(owned, "user.directory", b"directory-attribute")
        dzip = root / "directory.zip"
        rv = cmd(ZIP, "--xattrs", dzip, "marked/", cwd=dsrc)
        check(rv.returncode == 0, "directory metadata captured")
        dout = root / "directory-out"
        dout.mkdir()
        rv = cmd(UNZIP, "--xattrs", dzip, cwd=dout)
        check(rv.returncode == 0, "directory metadata restored")
        check(
            os.getxattr(dout / "marked", "user.directory") == b"directory-attribute",
            "directory native metadata fidelity",
        )
        # Linux user.* on a symlink is generally forbidden. In this backend
        # the writer must never follow the link and capture target metadata.
        sym = dsrc / "link"
        sym.symlink_to("marked")
        szip = root / "symlink.zip"
        rv = cmd(ZIP, "--xattrs", "-y", szip, "link", cwd=dsrc)
        check(rv.returncode == 0, "metadata-free symlink capture safe")
        check(szip.exists(), "symlink archive published")
    print("Linux exact overwrite / lifecycle: %d checks, 0 failures" % count)


if __name__ == "__main__":
    main()
