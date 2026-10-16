#!/usr/bin/env python3
"""M5D Linux directory xattrs: real writer/extractor lifecycle and negatives."""

import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
ZIP = pathlib.Path(os.environ.get("XTR_ZIP_BIN", HERE.parent / "zip30/zip"))
UNZIP = pathlib.Path(os.environ.get("XTR_UNZIP_BIN", HERE.parent / "unzip60/unzip"))
checks = 0


def ck(ok, why):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(why)


def run(*argv, cwd=None):
    return subprocess.run(
        [str(x) for x in argv],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=50,
    )


def attrs(p):
    return {k: os.getxattr(p, k) for k in os.listxattr(p)}


def zipdir(base, label, values):
    src = base / (label + "-src")
    src.mkdir()
    a = src / "d"
    (a / "sub").mkdir(parents=True)
    (a / "sub" / "f").write_bytes(b"contents")
    for k, v in values.items():
        os.setxattr(a, k, v)
    archive = base / (label + ".zip")
    os.chmod(a, 0o555)
    rv = run(ZIP, "--xattrs", "-r", archive, "d", cwd=src)
    os.chmod(a, 0o755)  # allow temporary test-tree cleanup
    ck(rv.returncode == 0, "zip %s %r" % (label, rv.stderr))
    return archive, src


def verify(base, label, values, large=False):
    arc, _ = zipdir(base, label, values)
    with zipfile.ZipFile(arc) as z:
        contents = z.namelist()
        ck("d/" in contents and "d/sub/" in contents, "directory members present")
        ck(
            any(n.startswith("__XTRO_ZIP__/") for n in contents) == large,
            "companion selection " + label,
        )
    dest = base / (label + "-dst")
    dest.mkdir()
    rv = run(UNZIP, "--xattrs", arc, cwd=dest)
    ck(rv.returncode == 0, "unzip %s %r" % (label, rv.stderr))
    ck(attrs(dest / "d") == values, "directory native attrs " + label)
    ck(
        (dest / "d").stat().st_mode & 0o777 == 0o555,
        "readonly final directory permissions " + label,
    )
    ck((dest / "d/sub/f").read_bytes() == b"contents", "nested contents " + label)
    ck(not (dest / "__XTRO_ZIP__").exists(), "private companion " + label)
    ck(attrs(dest / "d/sub") == {}, "unrelated child dir attrs " + label)
    # Existing directories are not extracted by this version of UnZip and
    # must never have their previous attribute values replaced.
    old = attrs(dest / "d")
    os.chmod(dest / "d", 0o755)
    os.setxattr(dest / "d", "user.existing", b"keep")
    before = attrs(dest / "d")
    rv = run(UNZIP, "--xattrs", "-o", arc, cwd=dest)
    ck(rv.returncode == 0, "existing directory extract " + label)
    ck(attrs(dest / "d") == before, "skipped directory unchanged " + label)
    ck(old.items() <= attrs(dest / "d").items(), "existing values retained")
    disabled = base / (label + "-disabled")
    disabled.mkdir()
    rv = run(UNZIP, "--no-xattrs", arc, cwd=disabled)
    ck(rv.returncode == 0, "disabled extraction " + label)
    ck(attrs(disabled / "d") == {}, "disabled directory attrs " + label)
    via = base / (label + "-via")
    rv = run(UNZIP, "--xattrs", arc, "-d", via)
    ck(rv.returncode == 0, "exdir " + label + " " + repr(rv.stderr))
    ck(attrs(via / "d") == values, "exdir attrs " + label)
    return arc


def mutate_local(arc, out, mode):
    raw = bytearray(arc.read_bytes())
    with zipfile.ZipFile(arc) as z:
        info = z.getinfo("d/")
        pos = info.header_offset
    namelen, extralen = struct.unpack_from("<HH", raw, pos + 26)
    start = pos + 30 + namelen
    end = start + extralen
    at = start
    changed = False
    while at + 4 <= end:
        ident, length = struct.unpack_from("<HH", raw, at)
        if ident == 0x5854 and length >= 40:
            if mode == "owner":
                raw[at + 4 + 8] ^= 0x40
            elif mode == "size":
                raw[pos + 22] ^= 1
            else:
                raw[at + 4] ^= 1
            changed = True
            break
        at += 4 + length
    ck(changed, "local Xtro field located")
    out.write_bytes(raw)


def main():
    tempdir = "/dev/shm" if os.path.isdir("/dev/shm") else None
    with tempfile.TemporaryDirectory(prefix="xtro-m5d-", dir=tempdir) as td:
        root = pathlib.Path(td)
        values = {"user.note": b"\x00\xff\x02abc", "user.empty": b""}
        archive = verify(root, "inline", values)
        large = {
            "user.huge": bytes(range(251)) * 239,
            "user.more": bytes(range(220)) * 66,
        }
        verify(root, "large", large, True)
        for what in ("owner", "magic", "size"):
            altered = root / ("bad-" + what + ".zip")
            mutate_local(archive, altered, what)
            dest = root / ("bad-" + what + "-dst")
            dest.mkdir()
            rv = run(UNZIP, "--xattrs", altered, cwd=dest)
            ck(rv.returncode != 0, "corrupted directory metadata rejected " + what)
            if what != "size":
                ck(
                    not (dest / "d").exists(),
                    "invalid dir rejected before creation " + what,
                )
            else:
                ck(
                    not (dest / "d").exists() or attrs(dest / "d") == {},
                    "size error never applies xattrs",
                )
        # The source filesystem normally has no user.* namespace on links;
        # --xattrs must still allow the ordinary archive/link round trip.
        src = root / "link-src"
        src.mkdir()
        (src / "file").write_text("target")
        os.setxattr(src / "file", "user.targetonly", b"do not inherit")
        (src / "link").symlink_to("file")
        arc = root / "link.zip"
        rv = run(ZIP, "--xattrs", "-y", arc, "link", cwd=src)
        ck(rv.returncode == 0, "metadata-free symlink archived " + repr(rv.stderr))
        dest = root / "link-dst"
        dest.mkdir()
        rv = run(UNZIP, "--xattrs", arc, cwd=dest)
        ck(rv.returncode == 0, "metadata-free symlink restored " + repr(rv.stderr))
        ck((dest / "link").is_symlink(), "symlink type preserved")
        ck(os.readlink(dest / "link") == "file", "symlink target preserved")
        # The symlink itself may not inherit attrs belonging to its referent.
        ck(
            not os.listxattr(dest / "link", follow_symlinks=False),
            "target metadata never applied to symlink",
        )
        print("Linux M5D directory/symlink tests: %d checks, 0 failures" % checks)


if __name__ == "__main__":
    main()
