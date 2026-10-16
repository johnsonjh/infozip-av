#!/usr/bin/env python3
"""Native FreeBSD 15+ named-attribute ZIP round trip (run on ZFS xattr=dir).

For NetBSD and FreeBSD without O_NAMEDATTR, run check-bsd-native instead.
A SKIP is not a successful native named-attribute test.
"""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


def run(args, *, cwd=None, input=None, ok=True):
    p = subprocess.run(
        list(map(str, args)),
        cwd=cwd,
        input=input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
    )
    if ok and p.returncode:
        raise RuntimeError(
            "%s failed (%d): %s"
            % (args, p.returncode, p.stderr.decode(errors="replace"))
        )
    return p


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    base = Path(__file__).resolve().parent.parent
    parser.add_argument("--workdir", help="Writable ZFS filesystem with xattr=dir")
    parser.add_argument("--zip", default=str(base / "zip30" / "zip"))
    parser.add_argument("--unzip", default=str(base / "unzip60" / "unzip"))
    args = parser.parse_args()
    if not sys.platform.startswith("freebsd"):
        print(
            "SKIP: FreeBSD 15+ named-attribute test not applicable to " + sys.platform
        )
        return 77
    with tempfile.TemporaryDirectory(
        prefix="xtro-native-stream-", dir=args.workdir
    ) as temp:
        root = Path(temp)
        tool = root / "probe"
        src = root / "src"
        dst = root / "dst"
        src.mkdir()
        dst.mkdir()
        code = Path(__file__).with_name("bsd_named_native_tool.c")
        run(["cc", "-std=c89", "-Wall", "-Wextra", "-O2", "-o", tool, code])
        one = src / "one"
        one.write_bytes(bytes(range(256)) * 10)
        (src / "folder").mkdir()
        cap = run([tool, "cap", one], ok=False)
        if cap.returncode == 77 or cap.stdout.split()[:1] != [b"1"]:
            print(
                "SKIP: O_NAMEDATTR unavailable on target filesystem: " + str(cap.stdout)
            )
            return 77
        checks = [0]

        def ck(value, text):
            checks[0] += 1
            if not value:
                raise AssertionError(text)

        def put(path, name, data, mode="0600"):
            run([tool, "put", path, name, mode], input=data)

        def get(path, name):
            return run([tool, "get", path, name]).stdout

        payload = bytes(range(256)) * 512  # 128 KiB, requires a ZIP companion
        put(one, "big", payload, "0640")
        put(one, "empty", b"", "0644")
        put(src / "folder", "directory", b"\x00\xff", "0600")
        ck(get(one, "big") == payload, "native setup")
        # File-like attributes can coexist with the traditional interface.
        # On some configurations the two views alias. Verify results using
        # both interfaces but do not assume either relationship.
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        setter = libc.extattr_set_file
        setter.restype = ctypes.c_ssize_t
        setter.argtypes = [
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
        ]
        getter = libc.extattr_get_file
        getter.restype = ctypes.c_ssize_t
        getter.argtypes = setter.argtypes

        def get_traditional(path, name):
            n = getter(os.fsencode(path), 1, name.encode(), None, 0)
            if n < 0:
                raise OSError(ctypes.get_errno(), "extattr_get_file " + name)
            result = ctypes.create_string_buffer(max(1, n))
            rv = getter(os.fsencode(path), 1, name.encode(), result, n)
            ck(rv == n, "traditional attribute read length")
            return result.raw[:n]

        ea = b"\xff\x00traditional\x01"
        buf = ctypes.create_string_buffer(ea)
        if setter(os.fsencode(one), 1, b"tradonly", buf, len(ea)) < 0:
            raise OSError(ctypes.get_errno(), "extattr_set_file")
        put(one, "shared", b"named-value")
        shared = b"traditional-same-name"
        sharedbuf = ctypes.create_string_buffer(shared)
        if setter(os.fsencode(one), 1, b"shared", sharedbuf, len(shared)) < 0:
            raise OSError(ctypes.get_errno(), "extattr_set_file shared")
        # The source filesystem may alias the two interfaces or keep distinct
        # same-name records. Record observed behavior instead of assuming it.
        expected_named = get(one, "shared")
        expected_extattr = get_traditional(one, "shared")
        run([tool, "settimes", one, "big", "1234000000", "1235000000"])
        print(
            "same-name mapping: "
            + ("alias" if expected_named == expected_extattr else "distinct")
        )
        run([args.zip, "-q", "-r", "--xattrs", "named.zip", "one", "folder"], cwd=src)
        archive = src / "named.zip"
        with zipfile.ZipFile(archive) as z:
            ck(len(z.namelist()) == 3, "owner/dir/companion")
            ck(any("__XTRO_ZIP__/" in n for n in z.namelist()), "companion exists")
        run([args.unzip, "-q", "--xattrs", archive], cwd=dst)
        ck(
            run([tool, "times", dst / "one", "big"]).stdout.strip()
            == b"1234000000 123456789 1235000000 987654321",
            "atime and mtime of restored stream",
        )
        ck(get(dst / "one", "big") == payload, "128 KiB stream")
        ck(
            get_traditional(dst / "one", "tradonly") == ea,
            "traditional EA alongside named streams",
        )
        ck(get(dst / "one", "shared") == expected_named, "same-name named stream")
        ck(
            get_traditional(dst / "one", "shared") == expected_extattr,
            "same-name extattr",
        )
        ck(get(dst / "one", "empty") == b"", "empty stream")
        ck(get(dst / "folder", "directory") == b"\x00\xff", "directory stream")
        ck(
            run([tool, "mode", dst / "one", "big"]).stdout.strip() == b"0640",
            "stream mode",
        )
        run([tool, "settimes", one, "big", "1234000000", "1235000000"])
        run(
            [args.zip, "-q", "-P", "correct", "--xattrs", "encrypted.zip", "one"],
            cwd=src,
        )
        encrypted = root / "encrypted"
        encrypted.mkdir()
        run(
            [args.unzip, "-q", "-P", "correct", "--xattrs", src / "encrypted.zip"],
            cwd=encrypted,
        )
        ck(
            run([tool, "times", encrypted / "one", "big"]).stdout.strip()
            == b"1234000000 123456789 1235000000 987654321",
            "ZipCrypto stream timestamps",
        )
        ck(get(encrypted / "one", "big") == payload, "ZipCrypto stream round trip")
        wrong = root / "wrong"
        wrong.mkdir()
        ck(
            run(
                [args.unzip, "-q", "-P", "wrong", "--xattrs", src / "encrypted.zip"],
                cwd=wrong,
                ok=False,
            ).returncode
            != 0,
            "wrong password rejected",
        )
        print("FreeBSD named-stream native round trip: %d checks passed" % checks[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
