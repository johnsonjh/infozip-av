#!/usr/bin/env python3
"""Regression checks for UT/UX/PKUNIX timestamp interpretation in UnZip."""

import argparse
import datetime
import os
import pathlib
import struct
import subprocess
import tempfile
import zipfile

# (name, DOS date, raw 32-bit Unix timestamp, expected POSIX seconds)
CASES = [
    ("zero_time", (1980, 1, 1, 0, 0, 0), 0, 0),
    ("normal_2010", (2010, 1, 1, 0, 0, 0), 1262304000, 1262304000),
    ("late_2037", (2037, 12, 31, 0, 0, 0), 2145830400, 2145830400),
    ("last_signed_2038", (2038, 1, 19, 3, 14, 6), 0x7FFFFFFF, 0x7FFFFFFF),
    ("first_unsigned_2038", (2038, 1, 19, 3, 14, 8), 0x80000000, 0x80000000),
    ("future_2040", (2040, 1, 1, 0, 0, 0), 2208988800, 2208988800),
    ("future_2100", (2100, 1, 1, 0, 0, 0), 4102444800, 4102444800),
    ("future_2106", (2106, 2, 7, 6, 28, 14), 0xFFFFFFFF, 0xFFFFFFFF),
    ("negative_one", (1980, 1, 1, 0, 0, 0), 0xFFFFFFFF, -1),
    ("negative_1969", (1980, 1, 1, 0, 0, 0), 0xFD0C2400, -49536000),
    ("ambiguous_2001", (2001, 1, 1, 0, 0, 0), 0x80000000, 978307200),
    ("ambiguous_1981", (1981, 1, 1, 0, 0, 0), 0xFFFFFFFF, 347155200),
]


def extra_field(kind, raw, mode="all"):
    if kind == "UT":
        if mode == "all":
            body = struct.pack("<BIII", 7, raw, raw, raw)
        elif mode == "truncated":
            body = struct.pack("<BI", 7, raw)
        elif mode == "only_atime":
            body = struct.pack("<BI", 2, raw)
        else:
            raise ValueError(mode)
        return struct.pack("<HH", 0x5455, len(body)) + body
    if kind == "UX":
        body = struct.pack("<II", raw, raw)
        return struct.pack("<HH", 0x5855, len(body)) + body
    if kind == "PKUX":
        body = struct.pack("<II", raw, raw)
        return struct.pack("<HH", 0x000D, len(body)) + body
    raise ValueError(kind)


def dos_time(dt):
    return int(datetime.datetime(*dt, tzinfo=datetime.timezone.utc).timestamp())


def make_archive(path, member, dt, raw, kind, mode="all"):
    zi = zipfile.ZipInfo(member, date_time=dt)
    zi.create_system = 3
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.extra = extra_field(kind, raw, mode)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(zi, b"Y2038 payload\n")


def extract_check(binary, root, kind, name, dt, raw, expected, mode="all", atime=None):
    arc = root / (kind + "-" + name + ".zip")
    dest = root / (kind + "-" + name)
    dest.mkdir()
    member = "example.txt"
    make_archive(arc, member, dt, raw, kind, mode)
    p = subprocess.run(
        [str(binary), "-oq", str(arc), "-d", str(dest)],
        env={**os.environ, "TZ": "UTC"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )
    target = dest / member
    if not target.is_file():
        raise AssertionError(
            "%s/%s: rc=%s stderr=%r" % (kind, name, p.returncode, p.stderr)
        )
    st = target.stat()
    actual = int(st.st_mtime)
    if p.returncode != 0 or actual != expected:
        raise AssertionError(
            "%s/%s: rc=%s mtime=%s expected=%s stderr=%r"
            % (kind, name, p.returncode, actual, expected, p.stderr)
        )
    if atime is not None and int(st.st_atime) != atime:
        raise AssertionError(
            "%s/%s: atime=%s expected=%s" % (kind, name, int(st.st_atime), atime)
        )
    if target.read_bytes() != b"Y2038 payload\n":
        raise AssertionError("%s/%s: contents differ" % (kind, name))


def check_generated_zip(binary, unzip_binary, root):
    zipcode = root / "input_file.txt"
    ziptool = binary.resolve()
    for year in (2038, 2040, 2100, 2106):
        t = int(datetime.datetime(year, 1, 1, tzinfo=datetime.timezone.utc).timestamp())
        zipcode.write_bytes(b"roundtrip\n")
        os.utime(zipcode, (t, t))
        zippath = root / ("created_%d.zip" % year)
        p = subprocess.run(
            [str(ziptool), "-q", str(zippath), zipcode.name],
            cwd=root,
            env={**os.environ, "TZ": "UTC"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        if p.returncode:
            raise AssertionError("Zip creation %d failed: %s" % (year, p.stderr))
        with zipfile.ZipFile(zippath) as archive:
            info = archive.getinfo(zipcode.name)
            if archive.read(info) != b"roundtrip\n":
                raise AssertionError("Zip payload mismatch")
            if b"UT" not in info.extra:
                raise AssertionError("Zip omitted UT field")
        folder = root / ("zip_roundtrip_%s" % year)
        folder.mkdir()
        restored = subprocess.run(
            [str(unzip_binary), "-oq", str(zippath), "-d", str(folder)],
            env={**os.environ, "TZ": "UTC"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        output = folder / zipcode.name
        if (
            restored.returncode
            or not output.is_file()
            or int(output.stat().st_mtime) != t
        ):
            raise AssertionError(
                "Zip->UnZip future-date roundtrip failed %d: %r"
                % (year, restored.stderr)
            )


def check_native_time_models(cc, source, root, compile_m32=False):
    content = source.read_text()
    start = content.index("static int ut32_interpretation(raw, dos_mdatetime)")
    end = content.index("/* Function ef_scan_for_izux() */", start)
    helpers = content[start:end]
    count = 0
    for ul in ("unsigned int", "unsigned long"):
        for model, ty in (
            ("signed32", "int"),
            ("unsigned32", "unsigned int"),
            ("signed64", "long long"),
            ("floating", "double"),
        ):
            for special in (False, True):
                wide = model in ("signed64", "floating", "unsigned32")
                pre = model != "unsigned32"
                code = "\n".join(
                    [
                        "typedef " + ul + " ulg;",
                        "typedef " + ty + " time_t;",
                        "#define DOSTIME_MINIMUM ((ulg)0x00210000UL)",
                        "#define DOSTIME_2038_01_18 ((ulg)0x74320000UL)",
                        "#define TRUE 1",
                        "#define FALSE 0",
                        (
                            "#define TIME_T_TYPE_DOUBLE 1"
                            if special
                            else "/* ordinary time_t */"
                        ),
                        helpers,
                        "int main(void) {",
                        "time_t t = (time_t)0;",
                        "int d = ut32_interpretation((ulg)0xffffffffUL, DOSTIME_MINIMUM);",
                        "int a = ut32_to_time((ulg)0xffffffffUL, d, &t);",
                        "if (a != " + ("1" if pre else "0") + ") return 2;",
                        "if (a && t != (time_t)-1) return 3;",
                        "d = ut32_interpretation((ulg)0x80000000UL, (ulg)0x78000000UL);",
                        "a = ut32_to_time((ulg)0x80000000UL, d, &t);",
                        "if (a != " + ("1" if wide else "0") + ") return 4;",
                        "if (a && t != (time_t)2147483648ULL) return 5;",
                        "d = ut32_interpretation((ulg)0x80000000UL, (ulg)0x42000000UL);",
                        "a = ut32_to_time((ulg)0x80000000UL, d, &t);",
                        "if (a) return 6;",
                        "return 0;",
                        "}",
                    ]
                )
                cfile = root / (
                    "model_%s_%s_%s.c" % (model, ul.replace(" ", "_"), int(special))
                )
                exe = cfile.with_suffix("")
                cfile.write_text(code)
                proc = subprocess.run(
                    [
                        cc,
                        "-std=gnu89",
                        "-O2",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        str(cfile),
                        "-o",
                        str(exe),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if proc.returncode:
                    raise AssertionError(
                        "%s compile failed: %s" % (cfile.name, proc.stderr)
                    )
                if compile_m32:
                    obj = cfile.with_suffix(".o")
                    test32 = subprocess.run(
                        [
                            cc,
                            "-m32",
                            "-std=gnu89",
                            "-O2",
                            "-Wall",
                            "-Wextra",
                            "-Werror",
                            "-c",
                            str(cfile),
                            "-o",
                            str(obj),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    if test32.returncode:
                        raise AssertionError(
                            "%s 32-bit syntax failed: %s" % (cfile.name, test32.stderr)
                        )
                proc = subprocess.run([str(exe)], timeout=10)
                if proc.returncode:
                    raise AssertionError(
                        "%s failed with %s" % (cfile.name, proc.returncode)
                    )
                count += 1
    return count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--unzip", type=pathlib.Path, required=True)
    parser.add_argument("--zip", type=pathlib.Path)
    parser.add_argument("--model-source", type=pathlib.Path)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--model-compile-m32", action="store_true")
    args = parser.parse_args()
    binary = args.unzip.resolve()
    total = 0
    with tempfile.TemporaryDirectory(prefix="xtro-y2038-") as temp:
        root = pathlib.Path(temp)
        for kind in ("UT", "UX", "PKUX"):
            for name, dt, raw, expected in CASES:
                extract_check(
                    binary, root, kind, name, dt, raw, expected, atime=expected
                )
                total += 1
                print("PASS", kind, name)
        for name, dt, raw, expected in CASES:
            if name in ("negative_one", "future_2040", "ambiguous_2001"):
                extract_check(
                    binary,
                    root,
                    "UT",
                    name + "_truncated",
                    dt,
                    raw,
                    expected,
                    mode="truncated",
                )
                total += 1
                print("PASS", name, "truncated UT")
        # A high-bit access-only UT field is ambiguous without a modtime.
        extract_check(
            binary,
            root,
            "UT",
            "atime_without_mtime",
            (2001, 1, 1, 0, 0, 0),
            0x80000000,
            978307200,
            mode="only_atime",
        )
        total += 1
        print("PASS atime without mtime")
        if args.model_source:
            count = check_native_time_models(
                args.cc, args.model_source.resolve(), root, args.model_compile_m32
            )
            total += count
            print("PASS %d time_t/unsigned-long model checks" % count)
        if args.zip:
            check_generated_zip(args.zip, binary, root)
            total += 4
            print("PASS four future Zip-created archives")
    print("%d total checks passed" % total)


if __name__ == "__main__":
    main()
