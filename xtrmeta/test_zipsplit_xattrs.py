#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""M6D ZipSplit: pair-aware byte-copy, size planning and native restoration."""

import hashlib
import os
import pathlib
import shutil
import struct
import subprocess
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ZIP = ROOT / "zip30/zip"
SPLIT = pathlib.Path(
    os.environ.get("XTRO_ZIPSPLIT_TEST_BINARY", str(ROOT / "zip30/zipsplit"))
)
UNZIP = ROOT / "unzip60/unzip"
checks = 0


def check(value, message):
    global checks
    checks += 1
    if not value:
        raise AssertionError(message)


def run(*args, cwd=None, expect=0):
    proc = subprocess.run(
        [str(x) for x in args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
    )
    if expect:
        check(proc.returncode != 0, "expected failure %r" % (args,))
    else:
        check(
            proc.returncode == 0,
            "%r returned %d: %s %s"
            % (args, proc.returncode, proc.stdout[-800:], proc.stderr[-800:]),
        )
    return proc


def xids(entry):
    p = entry.extra
    at = 0
    while at < len(p):
        check(at + 4 <= len(p), "extra length")
        ident, n = struct.unpack_from("<HH", p, at)
        check(at + 4 + n <= len(p), "extra data bounds")
        if ident == 0x5854 and p[at + 4 : at + 8] == b"XTRO":
            return p[at + 12 : at + 28]
        at += 4 + n
    return None


def selected_extra(entry):
    data = entry.extra
    chosen = []
    at = 0
    while at < len(data):
        ident, n = struct.unpack_from("<HH", data, at)
        end = at + 4 + n
        if ident in (0x5854, 0x9901, 0x4B46):
            chosen.append(data[at:end])
        at = end
    return chosen


def fixture(home, mode):
    d = home / mode
    d.mkdir()
    names = ["meta.bin", "ordinary1.bin", "ordinary2.bin", "ordinary3.bin"]
    data = {}
    for i, name in enumerate(names):
        value = os.urandom((9 if mode == "ae2" else 2500) if i == 0 else 9000)
        (d / name).write_bytes(value)
        data[name] = value
    attrs = {b"user.note": b"\x00\xfeM6D\x00"}
    attrs[b"user.left"] = os.urandom(34000)
    attrs[b"user.right"] = os.urandom(34000)
    for key, val in attrs.items():
        os.setxattr(d / names[0], key, val)
    opts = ["--xattrs"]
    if mode == "zip64":
        opts += ["-fz"]
    if mode == "crypto":
        opts += ["-P", "secret"]
    if mode == "ae3":
        opts += ["--aes-mode", "quantum", "--aes-strength", "256", "-eP", "secret"]
    if mode == "ae2":
        opts += ["--aes-strength", "256", "-eP", "secret"]
    if mode == "fwkcs":
        opts += ["--fwkcs-md5"]
    run(ZIP, *opts, "archive.zip", *names, cwd=d)
    return d, data, attrs


def split_test(home, mode, planner, extra=()):
    d, data, attrs = fixture(home, mode)
    original_hash = hashlib.sha256((d / "archive.zip").read_bytes()).digest()
    with zipfile.ZipFile(d / "archive.zip") as initial:
        original_fields = {e.filename: selected_extra(e) for e in initial.infolist()}
    result = run(SPLIT, *planner, *extra, "-n", "80000", "archive.zip", cwd=d)
    check(
        hashlib.sha256((d / "archive.zip").read_bytes()).digest() == original_hash,
        "input archive not rewritten",
    )
    parts = sorted(d.glob("archiv[0-9]*.zip")) + sorted(d.glob("archive[0-9]*.zip"))
    parts = list(dict.fromkeys(parts))
    check(len(parts) >= 2, "multiple output archives")
    allnames = []
    pair_part = None
    for p in parts:
        check(p.stat().st_size <= 80000, "max size cap respected")
        with zipfile.ZipFile(p) as z:
            names = z.namelist()
            allnames.extend(names)
            for e in z.infolist():
                check(
                    selected_extra(e) == original_fields[e.filename],
                    "Xtro/FWKCS/AES fields retained without modification",
                )
                if mode in ("ae2", "ae3") and e.filename in (
                    "meta.bin",
                    next((n for n in names if n.startswith("__XTRO_ZIP__/x/")), ""),
                ):
                    aes = [b for b in selected_extra(e) if b[:2] == b"\x01\x99"]
                    check(
                        len(aes) == 1
                        and struct.unpack_from("<H", aes[0], 4)[0]
                        == (2 if mode == "ae2" else 3),
                        "AES vendor version retained",
                    )
            side = [name for name in names if name.startswith("__XTRO_ZIP__/x/")]
            check(bool(side) == ("meta.bin" in names), "no orphaned metadata")
            if side:
                check(len(side) == 1, "exactly one companion")
                ident = xids(z.getinfo("meta.bin"))
                check(ident is not None, "central metadata preserved")
                check(
                    side[0].split("/")[-1].startswith(ident.hex()), "owner ID matches"
                )
                pair_part = p
            for entry in z.infolist():
                if entry.filename in data and entry.filename != "meta.bin":
                    check(xids(entry) is None, "ordinary entry has no Xtro field")
        run(UNZIP, "-tq", "-P", "secret", p, cwd=d)
    check(set(data).issubset(allnames), "all source files retained")
    check(allnames.count("meta.bin") == 1, "owner not duplicated")
    check(pair_part is not None, "owner restored with its companion")
    restored = d / "restored"
    restored.mkdir()
    run(UNZIP, "-o", "--xattrs", "-P", "secret", pair_part, "-d", restored, cwd=d)
    check((restored / "meta.bin").read_bytes() == data["meta.bin"], "content unchanged")
    for k, v in attrs.items():
        check(os.getxattr(restored / "meta.bin", k) == v, "xattr values restored")
    check(not (restored / "__XTRO_ZIP__").exists(), "no visible companion output")
    return d


def inline_test(home):
    d = home / "inline"
    d.mkdir()
    names = ["small.bin", "plain.bin"]
    for name in names:
        (d / name).write_bytes(os.urandom(8000))
    os.setxattr(d / names[0], b"user.inline", b"\x00\xff")
    run(ZIP, "--xattrs", "inline.zip", *names, cwd=d)
    run(SPLIT, "-n", "12000", "inline.zip", cwd=d)
    parts = sorted(d.glob("inlin[0-9]*.zip")) + sorted(d.glob("inline[0-9]*.zip"))
    parts = list(dict.fromkeys(parts))
    check(len(parts) >= 2, "inline split creates multiple archives")
    for part in parts:
        with zipfile.ZipFile(part) as z:
            if "small.bin" not in z.namelist():
                continue
            check(xids(z.getinfo("small.bin")) is not None, "inline metadata retained")
        out = d / "unpacked"
        out.mkdir(exist_ok=True)
        run(UNZIP, "-o", "--xattrs", part, "-d", out, cwd=d)
        check(
            os.getxattr(out / "small.bin", "user.inline") == b"\x00\xff",
            "inline xattr restored",
        )


def rejection(home):
    d, data, attrs = fixture(home, "failure")
    old = d / "archive.zip"
    original = old.read_bytes()
    # Both individual members fit but their combined footprint cannot.
    run(SPLIT, "-n", "69000", old, cwd=d, expect=1)
    check(old.read_bytes() == original, "input unchanged after group too large")
    check(not list(d.glob("archive[0-9]*.zip")), "no output after preflight failure")
    run(SPLIT, "-t", "-n", "80000", old, cwd=d)
    check(not list(d.glob("archive[0-9]*.zip")), "dry report emits no output")
    # Missing one companion in otherwise valid archive must reject upfront.
    with zipfile.ZipFile(old) as z:
        members = [
            (i, z.read(i.filename))
            for i in z.infolist()
            if not i.filename.startswith("__XTRO_ZIP__/")
        ]
    malformed = d / "malformed.zip"
    with zipfile.ZipFile(malformed, "w") as z:
        for info, payload in members:
            z.writestr(info, payload)
    run(SPLIT, "-n", "80000", malformed, cwd=d, expect=1)
    check(not list(d.glob("malforme[0-9]*.zip")), "malformed input has no output")
    # Ordinary archive behavior remains independently exercised.
    run(ZIP, "plain.zip", "ordinary1.bin", "ordinary2.bin", cwd=d)
    run(SPLIT, "-n", "12000", "plain.zip", cwd=d)
    # Two owners carry different metadata but the same file contents.
    multi = d / "multi"
    multi.mkdir()
    for filename, n in [("one.bin", 65), ("two.bin", 66)]:
        obj = multi / filename
        obj.write_bytes(b"IDENTICAL-CONTENT" * 150)
        os.setxattr(obj, "user.tag", bytes([n]))
        os.setxattr(obj, "user.largea", os.urandom(34000))
        os.setxattr(obj, "user.largeb", os.urandom(34000))
    run(ZIP, "--xattrs", "multi.zip", "one.bin", "two.bin", cwd=multi)
    run(SPLIT, "-n", "80000", "multi.zip", cwd=multi)
    subs = sorted(multi.glob("mult[0-9]*.zip")) + sorted(multi.glob("multi[0-9]*.zip"))
    subs = list(dict.fromkeys(subs))
    check(len(subs) == 2, "two independent pairs require two archives")
    all_seen = []
    for part in subs:
        with zipfile.ZipFile(part) as z:
            names = z.namelist()
            owners = [n for n in ("one.bin", "two.bin") if n in names]
            companions = [n for n in names if n.startswith("__XTRO_ZIP__/x/")]
            check(len(owners) == 1 and len(companions) == 1, "one pair per split")
            check(
                companions[0]
                .split("/")[-1]
                .startswith(xids(z.getinfo(owners[0])).hex()),
                "unique owner identity",
            )
            all_seen.extend(owners)
        out = multi / ("out_" + part.stem)
        out.mkdir()
        run(UNZIP, "-o", "--xattrs", part, "-d", out, cwd=multi)
        check(
            os.getxattr(out / owners[0], "user.tag")
            == os.getxattr(multi / owners[0], "user.tag"),
            "distinct owner xattr survives",
        )
    check(set(all_seen) == {"one.bin", "two.bin"}, "both independent owners emitted")


def main():
    where = pathlib.Path("/dev/shm") if pathlib.Path("/dev/shm").exists() else None
    with tempfile.TemporaryDirectory(prefix="xtro_split_", dir=where) as tmp:
        root = pathlib.Path(tmp)
        for mode, planner in [
            ("plain", ()),
            ("crypto", ()),
            ("ae2", ()),
            ("ae3", ()),
            ("fwkcs", ()),
            ("sequential", ("-s",)),
            ("zip64", ()),
        ]:
            split_test(root, mode, planner, ("-i",) if mode == "zip64" else ())
        rejection(root)
        inline_test(root)
    print("M6D ZipSplit Xtro association tests: %d checks, 0 failures" % checks)


if __name__ == "__main__":
    main()
