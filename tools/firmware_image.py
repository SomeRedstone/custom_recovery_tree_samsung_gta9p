#!/usr/bin/env python3
"""Extract images from a Samsung AP package."""

import argparse
import re
import sys
import tarfile
import zipfile
from pathlib import Path

from firmware_evidence import extract_member


def open_ap(firmware):
    if zipfile.is_zipfile(firmware):
        archive = zipfile.ZipFile(firmware)
        name = next(
            (n for n in archive.namelist() if re.search(r"(^|/)AP_.*\.tar(\.md5)?$", n)),
            None,
        )
        if not name:
            archive.close()
            raise SystemExit("no AP tar found in firmware zip")
        return archive, archive.open(name)
    return None, open(firmware, "rb")


def handle_extract(args):
    wanted = [item.strip() for item in args.images.split(",") if item.strip()]
    if not wanted:
        raise SystemExit("no images requested")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    remaining = dict.fromkeys(wanted)
    archive, stream = open_ap(Path(args.firmware))
    try:
        with tarfile.open(fileobj=stream, mode="r|", ignore_zeros=True) as tar:
            for member in tar:
                if not remaining:
                    break
                if not member.isfile():
                    continue
                base = Path(member.name).name
                stem = base[:-4] if base.endswith(".lz4") else base
                if stem not in remaining:
                    continue
                target = out_dir / stem
                with tar.extractfile(member) as source:
                    extract_member(member, source, target)
                print(f"extracted {base} -> {target}")
                del remaining[stem]
    finally:
        stream.close()
        if archive:
            archive.close()

    if remaining:
        raise SystemExit("not found in AP package: " + ", ".join(remaining))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware", required=True)
    parser.add_argument("--images", default="boot.img")
    parser.add_argument("--out", required=True)
    handle_extract(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
