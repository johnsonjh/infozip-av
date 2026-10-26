#!/usr/bin/env python3

import argparse
import errno
import os
import pty
import select
import signal
import struct
import sys
import tempfile
import time
import zipfile
from pathlib import Path


def get_payload(path):
    with zipfile.ZipFile(path) as archive:
        (entry,) = archive.infolist()
        assert entry.compress_type == 31340, entry.compress_type
        with path.open("rb") as handle:
            handle.seek(entry.header_offset)
            header = handle.read(30)
            assert header[:4] == b"PK\x03\x04"
            name_size, extra_size = struct.unpack_from("<HH", header, 26)
            handle.seek(name_size + extra_size, 1)
            data = handle.read(entry.compress_size)
            assert len(data) == entry.compress_size
            return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emu2", type=Path, required=True)
    parser.add_argument("--bin", type=Path, required=True)
    parser.add_argument("--upstream-dir", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.upstream_dir.resolve()))
    import tamp as upstream

    exe_dir = args.bin.resolve()
    emu2 = args.emu2.resolve()
    payload = (
        (b"ABCDABCDEFABCDEF123456789\r\n" * 190) + bytes(range(256)) * 7 + b"Z" * 500
    )

    with tempfile.TemporaryDirectory(prefix="tamp-8086-emu2-") as tmp:
        directory = Path(tmp)
        (directory / "INPUT.BIN").write_bytes(payload)

        def execute(program, *params, expected_error=None):
            command = [str(emu2), str(exe_dir / (program + ".exe")), *params]
            # Long-running emu2 programs poll the emulated keyboard, which
            # opens /dev/tty. Give each subprocess a real controlling PTY;
            # subprocess.run(stdout=PIPE) only works for very short programs.
            child, master = pty.fork()
            if child == 0:
                os.chdir(directory)
                os.execv(command[0], command)
            result_bytes = bytearray()
            deadline = time.monotonic() + 180.0
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        os.kill(child, signal.SIGKILL)
                        raise TimeoutError(command)
                    ready, _, _ = select.select([master], [], [], remaining)
                    if ready:
                        try:
                            data = os.read(master, 4096)
                        except OSError as exc:
                            if exc.errno == errno.EIO:
                                break
                            raise
                        if not data:
                            break
                        result_bytes.extend(data)
            finally:
                os.close(master)
            _, wait_status = os.waitpid(child, 0)
            code = os.waitstatus_to_exitcode(wait_status)
            output = bytes(result_bytes)
            if expected_error is not None:
                assert code != 0 and expected_error in output.lower(), (
                    command,
                    code,
                    output[-900:],
                )
                return output
            if (
                program == "unzip"
                and code == 1
                and b"TZ environment variable not found" in output
                and b"No errors detected in compressed data" in output
            ):
                # The emulator does not populate a DOS TZ environment entry.
                # Native UnZip reports a warning exit status despite valid
                # CRC-tested members; reject every other exit-1 diagnosis.
                return output
            if code:
                raise AssertionError(
                    f"{command!r} exited {code}: " f"{output[-900:]!r}"
                )
            return output

        for name, level, lazy in (
            ("T6.ZIP", 6, True),
            ("T7.ZIP", 7, True),
            ("T9.ZIP", 9, False),
            ("T11.ZIP", 11, True),
        ):
            # emu2 maps DOS-created filenames to lowercase host filenames.
            name = name.lower()
            print(f"DOS16 Tamp -{level} lazy={lazy}", flush=True)
            output = execute(
                "zip",
                "-q",
                "--disable-store-fallback",
                "-Z",
                "tamp",
                f"-{level}",
                "--tamp-lazy-matching" if lazy else "--tamp-lazy-matching-",
                name,
                "INPUT.BIN",
            )
            if not (directory / name).exists():
                raise AssertionError(
                    (name, output[-900:], sorted(x.name for x in directory.iterdir()))
                )
            stream = get_payload(directory / name)
            assert upstream.decompress(stream) == payload, name
            execute("unzip", "-t", name)
            print(f"PASS {name} {len(payload)} -> {len(stream)}", flush=True)

        for name, spelling in (("NO10.ZIP", "-10"), ("NO10LONG.ZIP", "--compress-10")):
            execute(
                "zip",
                "-q",
                "-Z",
                "tamp",
                spelling,
                name,
                "INPUT.BIN",
                expected_error=b"invalid argument",
            )
            assert not (directory / name.lower()).exists(), name
            print(f"PASS DOS16 rejection: {spelling}", flush=True)


if __name__ == "__main__":
    main()
