#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""Option B: real directory-owner encrypted companion regression on Linux.

The ZIP owner must remain clear while native EA values travel only in a
password-protected companion. This is NOT an OS/2 native filesystem test.
"""

import os
import pathlib
import subprocess
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
ZIP = HERE.parent / "zip30/zip"
UNZIP = HERE.parent / "unzip60/unzip"
SECRET = b"xtro-secret-directory-EA-value-marker-42F7BD0B"


def run(args, cwd):
    p = subprocess.run(
        [str(a) for a in args],
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
    )
    return p


def verify(label, mode, base):
    src = base / (label + "-source")
    src.mkdir()
    (src / "protected").mkdir()
    os.setxattr(src / "protected", "user.xtro-secret", SECRET)
    archive = base / (label + ".zip")
    cmd = [ZIP, "--xattrs"] + mode + [archive, "protected/"]
    p = run(cmd, src)
    assert p.returncode == 0, (label, p.stdout, p.stderr)
    raw = archive.read_bytes()
    assert SECRET not in raw and b"user.xtro-secret" not in raw, label
    with zipfile.ZipFile(archive) as z:
        owner, side = z.infolist()
        assert owner.filename == "protected/" and not (owner.flag_bits & 1)
        assert owner.file_size == 0 and side.flag_bits & 1
        assert side.filename.startswith("__XTRO_ZIP__/x/")
        assert owner.extra.count(b"XTRO") == 1
        assert owner.extra[owner.extra.index(b"XTRO") + 7] == 1
    good = base / (label + "-good")
    good.mkdir()
    p = run([UNZIP, "--xattrs", "-P", "test-password", archive], good)
    assert p.returncode == 0, (label, p.stdout, p.stderr)
    assert os.getxattr(good / "protected", "user.xtro-secret") == SECRET
    assert not (good / "__XTRO_ZIP__").exists()
    bad = base / (label + "-wrong-password")
    bad.mkdir()
    p = run([UNZIP, "--xattrs", "-P", "wrong-password", archive], bad)
    assert p.returncode != 0, (label, p.stdout, p.stderr)
    if (bad / "protected").exists():
        assert "user.xtro-secret" not in os.listxattr(bad / "protected")


def main():
    with tempfile.TemporaryDirectory(
        prefix="xtro-dir-secret-", dir="/dev/shm" if os.path.isdir("/dev/shm") else None
    ) as tmp:
        base = pathlib.Path(tmp)
        verify("zipcrypto", ["-P", "test-password"], base)
        verify("aes-2", ["-eP", "test-password"], base)
        verify(
            "aes-3",
            ["-eP", "test-password", "--aes-mode", "quantum", "--aes-strength", "256"],
            base,
        )
    print(
        "Encrypted directory EA companions: ZipCrypto, AE-2, AE-3, "
        "wrong-password rejection and no plaintext exposure PASS"
    )


if __name__ == "__main__":
    main()
