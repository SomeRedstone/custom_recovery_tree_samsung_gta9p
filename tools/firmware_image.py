#!/usr/bin/env python3
"""Extract a single image from a Samsung AP package."""

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
    archive, stream = open_ap(Path(args.firmware))
    try:
        with tarfile.open(fileobj=stream, mode="r|", ignore_zeros=True) as tar:
            for member in tar:
                if not member.isfile():
                    continue
                base = Path(member.name).name
                stem = base[:-4] if base.endswith(".lz4") else base
                if stem != args.image:
                    continue
                with tar.extractfile(member) as source:
                    extract_member(member, source, args.out)
                print(f"extracted {base} -> {args.out}")
                return
        raise SystemExit(f"{args.image} not found in AP package")
    finally:
        stream.close()
        if archive:
            archive.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware", required=True)
    parser.add_argument("--image", default="boot.img")
    parser.add_argument("--out", required=True)
    handle_extract(parser.parse_args())


if __name__ == "__main__":
    sys.exit(main())
