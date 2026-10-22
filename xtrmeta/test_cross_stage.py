#!/usr/bin/env python3
"""Regression: MinGW and DOS stage copies must include portable Xtro sources.

Uses host GNU make dry runs to test dependency graphs; does not purport to
cross-compile or execute PE/DOS binaries.
"""

import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
NAMES = (
    "xtrm.c",
    "xtrm.h",
    "xtrsha.c",
    "xtrsha.h",
    "xtrv1.c",
    "xtrv1.h",
    "xtrrewrite.h",
    "xtrverify_inline.h",
    "source_epoch.h",
    "source_epoch_times.h",
)


def run(args, *, cwd=None, expected=0):
    p = subprocess.run(args, cwd=cwd, text=True, capture_output=True)
    if p.returncode != expected:
        raise AssertionError(
            "Unexpected status %s (wanted %s) for %r:\n%s\n%s"
            % (p.returncode, expected, args, p.stdout, p.stderr)
        )
    return p


def main():
    for build in ("build-win32.sh", "build-dos386.sh"):
        text = (ROOT / build).read_text()
        assert "xtrmeta/stage-cross.sh" in text, build
        assert '"$STAGE/src/common/xtrlibdeflate_size.h"' in text, build
    with tempfile.TemporaryDirectory(prefix="xtro-cross-stage-") as td:
        src = pathlib.Path(td) / "src"
        src.mkdir()
        for name in ("zipopt", "zipdedup", "zip30", "unzip60"):
            # Symlink source trees: make dry-runs only, no target binaries.
            (src / name).symlink_to(ROOT / name, target_is_directory=True)
        common = src / "common"
        common.mkdir()
        shutil.copy2(ROOT / "common/xtrlibdeflate_size.h", common)
        assert (common / "xtrlibdeflate_size.h").read_bytes() == (
            ROOT / "common/xtrlibdeflate_size.h"
        ).read_bytes()
        stage = src / "xtrmeta"
        missing = run(
            [
                "sh",
                str(ROOT / "xtrmeta/stage-cross.sh"),
                str(ROOT / "xtrmeta-not-present"),
                str(stage),
            ],
            expected=1,
        )
        assert "Missing Xtro-ZIP cross-build input" in missing.stderr
        assert not stage.exists(), "Failed stage should not create output"
        run(
            [
                "sh",
                str(ROOT / "xtrmeta/stage-cross.sh"),
                str(ROOT / "xtrmeta"),
                str(stage),
            ]
        )
        assert sorted(p.name for p in stage.iterdir()) == sorted(NAMES)
        for name in NAMES:
            assert (stage / name).read_bytes() == (ROOT / "xtrmeta" / name).read_bytes()
        for tool in ("zipopt", "zipdedup"):
            for makefile in ("Makefile.win32", "Makefile.dos386"):
                # -n validates all dependency paths and recipes, and -j
                # checks their parallel-ready dependency graph.
                target = tool + ".exe"
                run(
                    [
                        "make",
                        "--no-print-directory",
                        "-n",
                        "-j",
                        "4",
                        "-f",
                        makefile,
                        target,
                    ],
                    cwd=src / tool,
                )
                print("Cross-stage prerequisites OK: %s / %s" % (tool, makefile))
        # Repeat staging to ensure this is safe in re-used build directories.
        run(
            [
                "sh",
                str(ROOT / "xtrmeta/stage-cross.sh"),
                str(ROOT / "xtrmeta"),
                str(stage),
            ]
        )
        assert len(list(stage.iterdir())) == len(NAMES)
    print("All cross-build staging regression checks passed")


if __name__ == "__main__":
    main()
