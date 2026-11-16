#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

SPARSE_MAGIC = 0xED26FF3A
LP_METADATA_MAGIC = b"0PLA"
AVB_FOOTER_MAGIC = b"AVBf"
AVB_VBMETA_MAGIC = b"AVB0"
DTBO_MAGIC = 0xD7B7AB1E
PANEL_PATTERN = re.compile(rb"qcom,mdss_dsi_[a-z0-9_]+_video_display")

BOOT_IMAGES = ("boot.img", "recovery.img", "init_boot.img", "vendor_boot.img")
VBMETA_IMAGES = ("vbmeta.img", "vbmeta_system.img")
DTBO_IMAGES = ("dtbo.img",)

ONE_UI_7_PDA = (
    "X216BXXU6DYD9",
    "X216BXXS7DYE3",
    "X216BXXS8DYG1",
    "X216BXXS8DYH1",
    "X216BXXS8DYI1",
    "X216BXXS9DYJ5",
)


def read_bytes(path, size=None):
    with open(path, "rb") as handle:
        return handle.read() if size is None else handle.read(size)


def decode_os_version(raw):
    if not raw:
        return None, None
    major = (raw >> 25) & 0x7F
    minor = (raw >> 18) & 0x7F
    patch = (raw >> 11) & 0x7F
    year = (raw >> 4) & 0x7F
    month = raw & 0x0F
    version = f"{major}.{minor}.{patch}"
    date = f"{2000 + year:04d}-{month:02d}" if 1 <= month <= 12 else None
    return version, date


def kernel_release(blob):
    marker = b"Linux version "
    index = blob.find(marker)
    if index < 0:
        return None
    end = blob.find(b"\0", index)
    if end < 0:
        end = index + 256
    fields = blob[index + len(marker):min(end, index + 256)].decode(
        "utf-8", "replace").split()
    return fields[0] if fields else None


def kernel_details(path, header):
    header_version = struct.unpack_from("<I", header, 40)[0]
    kernel_size = struct.unpack_from("<I", header, 8)[0]
    page_size = 4096 if header_version >= 3 else struct.unpack_from("<I", header, 36)[0]
    if kernel_size == 0 or page_size < 512:
        return {}
    with open(path, "rb") as handle:
        handle.seek(page_size)
        kernel = handle.read(kernel_size)
    return {
        "kernel_size": len(kernel),
        "kernel_sha256": hashlib.sha256(kernel).hexdigest(),
        "kernel_release": kernel_release(kernel),
    }


def dtbo_details(path):
    data = read_bytes(path)
    if len(data) >= 8:
        for endian in (">", "<"):
            if struct.unpack_from(endian + "I", data, 0)[0] != DTBO_MAGIC:
                continue
            total_size = struct.unpack_from(endian + "I", data, 4)[0]
            if 0 < total_size <= len(data):
                data = data[:total_size]
            break
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "panels": sorted({match.group().decode() for match in PANEL_PATTERN.finditer(data)}),
    }


def parse_boot_image(path):
    header = read_bytes(path, 4096)
    if header[:8] == b"VNDRBOOT":
        version = struct.unpack_from("<I", header, 8)[0]
        result = {"format": "vendor_boot", "header_version": version}
        if version in (3, 4):
            result["vendor_ramdisk_size"] = struct.unpack_from("<I", header, 24)[0]
            result["header_size"] = struct.unpack_from("<I", header, 2096)[0]
        avb = parse_avb_footer(path)
        if avb:
            result["avb"] = avb
        return result

    if header[:8] != b"ANDROID!":
        return {"error": "not an Android boot image"}

    header_version = struct.unpack_from("<I", header, 40)[0]
    if header_version >= 3:
        os_raw = struct.unpack_from("<I", header, 16)[0]
    else:
        os_raw = struct.unpack_from("<I", header, 44)[0]

    os_version, os_patch = decode_os_version(os_raw)
    result = {
        "format": "boot",
        "header_version": header_version,
        "os_version_raw": f"0x{os_raw:08x}",
        "os_version": os_version,
        "os_patch_level": os_patch,
    }
    result.update(kernel_details(path, header))

    avb = parse_avb_footer(path)
    if avb:
        result["avb"] = avb
    return result


def parse_avb_footer(path):
    size = os.path.getsize(path)
    if size < 64:
        return None
    with open(path, "rb") as handle:
        handle.seek(size - 64)
        footer = handle.read(64)
        if footer[:4] != AVB_FOOTER_MAGIC:
            return None
        original_size, vbmeta_offset, vbmeta_size = struct.unpack_from(">QQQ", footer, 12)
        if vbmeta_size == 0 or vbmeta_offset + vbmeta_size > size:
            return None
        handle.seek(vbmeta_offset)
        blob = handle.read(vbmeta_size)
    parsed = parse_vbmeta_blob(blob)
    if parsed:
        parsed["original_image_size"] = original_size
        parsed["vbmeta_offset"] = vbmeta_offset
    return parsed


def parse_vbmeta_blob(blob):
    if len(blob) < 256 or blob[:4] != AVB_VBMETA_MAGIC:
        return None
    major, minor = struct.unpack_from(">II", blob, 4)
    auth_size = struct.unpack_from(">Q", blob, 12)[0]
    aux_start = 256 + auth_size
    descriptors_offset, descriptors_size = struct.unpack_from(">QQ", blob, 96)
    rollback_index = struct.unpack_from(">Q", blob, 112)[0]
    flags, rollback_location = struct.unpack_from(">II", blob, 120)
    release = blob[128:176].split(b"\0")[0].decode("utf-8", "replace")
    props = {}
    start = aux_start + descriptors_offset
    descriptors = blob[start:start + descriptors_size]
    position = 0
    while position + 16 <= len(descriptors):
        tag, following = struct.unpack_from(">QQ", descriptors, position)
        payload = descriptors[position + 16:position + 16 + following]
        if tag == 0 and len(payload) >= 16:
            key_len, value_len = struct.unpack_from(">QQ", payload, 0)
            key = payload[16:16 + key_len].decode("utf-8", "replace")
            value_start = 17 + key_len
            value = payload[value_start:value_start + value_len].decode("utf-8", "replace")
            if key:
                props[key] = value
        position += 16 + following
    return {
        "version": f"{major}.{minor}",
        "release_string": release,
        "rollback_index": rollback_index,
        "flags": flags,
        "rollback_index_location": rollback_location,
        "props": props,
    }


def parse_vbmeta_image(path):
    blob = read_bytes(path)
    if blob[:4] == AVB_VBMETA_MAGIC:
        return parse_vbmeta_blob(blob)
    return parse_avb_footer(path)


def sparse_prefix(data, wanted):
    if len(data) < 28 or struct.unpack_from("<I", data, 0)[0] != SPARSE_MAGIC:
        return data[:wanted], len(data)

    file_header_size, chunk_header_size = struct.unpack_from("<HH", data, 8)
    block_size = struct.unpack_from("<I", data, 12)[0]
    total_blocks = struct.unpack_from("<I", data, 16)[0]
    position = file_header_size
    output = bytearray()
    while position + chunk_header_size <= len(data) and len(output) < wanted:
        chunk_type, _, chunk_blocks, total_size = struct.unpack_from("<HHII", data, position)
        if total_size < chunk_header_size:
            break
        payload_start = position + chunk_header_size
        payload_size = total_size - chunk_header_size
        if payload_start + payload_size > len(data):
            payload_size = max(0, len(data) - payload_start)
        remaining = wanted - len(output)
        if chunk_type == 0xCAC1:
            output.extend(data[payload_start:payload_start + min(payload_size, remaining)])
        elif chunk_type == 0xCAC2:
            fill = data[payload_start:payload_start + 4] or b"\0"
            output.extend((fill * ((remaining + 3) // 4 + 1))[:remaining])
        elif chunk_type == 0xCAC3:
            output.extend(b"\0" * remaining)
        position += total_size
    return bytes(output), total_blocks * block_size


def parse_super_prefix(path):
    data = read_bytes(path)
    raw, logical_size = sparse_prefix(data, 2 * 1024 * 1024)
    offset = raw.find(LP_METADATA_MAGIC)
    if offset < 0:
        return {"error": "LP metadata not found in super prefix"}

    header_size = struct.unpack_from("<I", raw, offset + 8)[0]
    tables = offset + header_size

    partitions = []
    position = tables
    while position + 52 <= len(raw) and len(partitions) < 256:
        name_bytes = raw[position:position + 36].split(b"\0")[0]
        if not re.fullmatch(rb"[A-Za-z0-9_]+", name_bytes):
            break
        _, _, num_extents, group_index = struct.unpack_from("<IIII", raw, position + 36)
        if num_extents > 100000 or group_index > 100:
            break
        partitions.append({
            "name": name_bytes.decode(),
            "group_index": group_index,
            "num_extents": num_extents,
        })
        position += 52

    groups = []
    for match in re.finditer(rb"[A-Za-z0-9_.-]{3,36}", raw):
        name = match.group().decode()
        if not (name.endswith("dynamic_partitions") or name in ("default", "main")):
            continue
        start = match.start()
        if start + 48 > len(raw):
            continue
        max_size = struct.unpack_from("<Q", raw, start + 40)[0]
        if not (0 < max_size <= 64 * 1024 ** 3 and max_size % 4096 == 0):
            continue
        if any(group["name"] == name for group in groups):
            continue
        groups.append({"name": name, "max_size": max_size})

    return {
        "logical_size": logical_size,
        "groups": groups,
        "partitions": [partition["name"] for partition in partitions],
        "partition_details": partitions,
    }


def load_expectations(root):
    board = (root / "BoardConfig.mk").read_text()
    product = (root / "twrp_gta9p.mk").read_text()
    expectations = {}
    match = re.search(
        r"BOARD_RECOVERY_MKBOOTIMG_ARGS\s*\+=\s*--os_version\s+(\S+)\s+--os_patch_level\s+(\S+)",
        board,
    )
    if match:
        expectations["os_version"] = match.group(1)
        expectations["os_patch_level"] = match.group(2)
    match = re.search(r"BOARD_SAMSUNG_DYNAMIC_PARTITIONS_SIZE\s*:=\s*(\d+)", board)
    if match:
        expectations["dynamic_partitions_size"] = int(match.group(1))
    block = re.search(
        r"BOARD_SAMSUNG_DYNAMIC_PARTITIONS_PARTITION_LIST\s*:=\s*((?:.*\\\n)*.*)",
        board,
    )
    if block:
        expectations["dynamic_partitions"] = re.findall(
            r"\b(system|system_ext|vendor|product|odm)\b", block.group(1)
        )
    match = re.search(r"TW_DEVICE_VERSION\s*:=\s*(\S+)", (root / "version.mk").read_text())
    if match:
        expectations["device_version"] = match.group(1)
    match = re.search(r"BUILD_FINGERPRINT\s*:=\s*(\S+)", product)
    if match:
        expectations["fingerprint"] = match.group(1)
    kernel = root / "prebuilt" / "Image"
    if kernel.exists():
        blob = read_bytes(kernel)
        expectations["kernel_release"] = kernel_release(blob)
        expectations["kernel_sha256"] = hashlib.sha256(blob).hexdigest()
    dtbo = root / "prebuilt" / "dtbo.img"
    if dtbo.exists():
        details = dtbo_details(dtbo)
        expectations["dtbo_sha256"] = details["sha256"]
        expectations["dtbo_panels"] = details["panels"]
    return expectations


def version_tuple(value):
    if not value:
        return None
    parts = [int(part) for part in re.findall(r"\d+", str(value))][:3]
    return tuple(parts + [0] * (3 - len(parts)))


def build_checks(evidence, expectations):
    checks = []

    def add(name, tree, firmware, ok, critical=False):
        checks.append({
            "name": name,
            "tree": tree,
            "firmware": firmware,
            "ok": ok,
            "critical": critical,
        })

    expected_version = expectations.get("os_version")
    expected_patch = expectations.get("os_patch_level")
    expected_patch_day = expected_patch + "-01" if expected_patch else None

    boot = evidence.get("boot") or {}
    recovery = evidence.get("recovery") or {}
    for image_name, image in (("boot", boot), ("recovery", recovery)):
        if not image or "error" in image:
            continue
        add(f"{image_name} header OS patch", expected_patch,
            image.get("os_patch_level"),
            image.get("os_patch_level") == expected_patch, critical=True)
        add(f"{image_name} header OS version", expected_version,
            image.get("os_version"),
            version_tuple(image.get("os_version")) == version_tuple(expected_version))

    for image_name in ("boot", "recovery"):
        image = evidence.get(image_name) or {}
        props = (image.get("avb") or {}).get("props", {})
        if not props:
            continue
        for prop in ("com.android.build.boot.security_patch",
                     "com.android.build.vendor.security_patch"):
            add(f"{image_name} {prop}", expected_patch_day, props.get(prop),
                props.get(prop) == expected_patch_day)
        for prop in ("com.android.build.boot.os_version",
                     "com.android.build.vendor.os_version"):
            add(f"{image_name} {prop}", expected_version, props.get(prop),
                version_tuple(props.get(prop)) == version_tuple(expected_version))

    vbmeta = evidence.get("vbmeta") or {}
    vbmeta_props = vbmeta.get("props", {})
    for prop in ("com.android.build.boot.security_patch",
                 "com.android.build.vendor.security_patch",
                 "com.android.build.system.security_patch"):
        add(f"vbmeta {prop}", expected_patch_day, vbmeta_props.get(prop),
            vbmeta_props.get(prop) == expected_patch_day, critical=True)
    add("vbmeta com.android.build.system.os_version", expected_version,
        vbmeta_props.get("com.android.build.system.os_version"),
        version_tuple(vbmeta_props.get("com.android.build.system.os_version"))
        == version_tuple(expected_version))
    add("vbmeta rollback index", 1, vbmeta.get("rollback_index"),
        vbmeta.get("rollback_index") in (0, 1))
    add("vbmeta flags", 3, vbmeta.get("flags"), vbmeta.get("flags") == 3)

    super_image = evidence.get("super") or {}
    groups = super_image.get("groups") or []
    firmware_size = groups[0]["max_size"] if groups else None
    add("super group size", expectations.get("dynamic_partitions_size"),
        firmware_size, firmware_size == expectations.get("dynamic_partitions_size"))
    tree_parts = expectations.get("dynamic_partitions") or []
    firmware_parts = super_image.get("partitions") or []
    add("super partitions", ",".join(tree_parts), ",".join(firmware_parts),
        set(tree_parts) == set(firmware_parts), critical=True)

    fingerprint = expectations.get("fingerprint")
    if fingerprint:
        fields = fingerprint.split("/")
        tree_pda = fields[4].split(":")[0] if len(fields) > 4 else None
        add("fingerprint PDA", tree_pda, expectations.get("pda"),
            tree_pda == expectations.get("pda"))

    expected_kernel = expectations.get("kernel_sha256")
    if expected_kernel:
        image = evidence.get("recovery") or {}
        if image and "error" not in image:
            add("recovery kernel sha256", expected_kernel,
                image.get("kernel_sha256"),
                image.get("kernel_sha256") == expected_kernel)

    expected_dtbo = expectations.get("dtbo_sha256")
    dtbo = evidence.get("dtbo") or {}
    if expected_dtbo and not dtbo:
        add("dtbo image", "present", "missing from AP tar", False)
    elif expected_dtbo:
        add("dtbo sha256", expected_dtbo, dtbo.get("sha256"),
            dtbo.get("sha256") == expected_dtbo)
    expected_panels = set(expectations.get("dtbo_panels") or [])
    firmware_panels = set(dtbo.get("panels") or [])
    if expected_panels and dtbo:
        missing = sorted(firmware_panels - expected_panels)
        add("dtbo panel overlays", f"{len(expected_panels)} panels",
            f"{len(firmware_panels)} panels"
            + (f"; missing {', '.join(missing)}" if missing else ""),
            not missing, critical=True)
    return checks


def evidence_markdown(evidence, checks):
    lines = [f"# Firmware evidence: {evidence['pda']} ({evidence['model']} / {evidence['csc']})", ""]
    lines += ["## Boot images", "", "| Image | Header | OS version | Patch | Kernel | AVB props |", "|---|---|---|---|---|---|"]
    for name in ("boot", "recovery", "init_boot", "vendor_boot"):
        image = evidence.get(name)
        if not image:
            continue
        if "error" in image:
            lines.append(f"| {name} | {image['error']} | | | | |")
            continue
        props = (image.get("avb") or {}).get("props", {})
        lines.append(
            f"| {name} | {image.get('header_version')} | {image.get('os_version')} | "
            f"{image.get('os_patch_level')} | {image.get('kernel_release') or '-'} | {len(props)} |"
        )
    lines += ["", "## VBMeta", "", "| Image | Release | Rollback | Props |", "|---|---|---|---|"]
    for name in ("vbmeta", "vbmeta_system"):
        image = evidence.get(name)
        if not image:
            continue
        lines.append(
            f"| {name} | {image.get('release_string')} | {image.get('rollback_index')} | "
            f"{len(image.get('props', {}))} |"
        )
    dtbo = evidence.get("dtbo") or {}
    if dtbo:
        panels = ", ".join(f"`{name}`" for name in dtbo.get("panels", []))
        lines += ["", "## DTBO", "",
                  f"Size: {dtbo.get('size')} bytes", "",
                  f"SHA256: `{dtbo.get('sha256')}`", "",
                  f"Panels: {panels}", ""]
    super_image = evidence.get("super") or {}
    if super_image and "error" not in super_image:
        lines += ["", "## Super", "", "| Group | Max size | Logical size |", "|---|---|---|"]
        for group in super_image.get("groups", []):
            lines.append(
                f"| {group['name']} | {group['max_size']} | {super_image.get('logical_size')} |"
            )
        lines += ["", "Partitions: " + ", ".join(super_image.get("partitions", [])), ""]
    lines += ["", "## Checks", "",
              "| Check | Tree | Firmware | Critical | Result |",
              "|---|---|---|---|---|"]
    for check in checks:
        if check["ok"]:
            result = "ok"
        else:
            result = "diff" if check["critical"] else "note"
        lines.append(
            f"| {check['name']} | {check['tree']} | {check['firmware']} | "
            f"{'yes' if check['critical'] else 'no'} | {result} |"
        )
    lines.append("")
    return "\n".join(lines)


def inspect_images(images, model, csc, pda, expectations):
    evidence = {"model": model, "csc": csc, "pda": pda}
    for name in ("boot", "recovery", "init_boot", "vendor_boot"):
        path = images / f"{name}.img"
        if path.exists():
            evidence[name] = parse_boot_image(path)
    for name in ("vbmeta", "vbmeta_system"):
        path = images / f"{name}.img"
        if path.exists():
            evidence[name] = parse_vbmeta_image(path)
    super_prefix = images / "super.prefix"
    if super_prefix.exists():
        evidence["super"] = parse_super_prefix(super_prefix)
    dtbo = images / "dtbo.img"
    if dtbo.exists():
        evidence["dtbo"] = dtbo_details(dtbo)
    expectations = dict(expectations)
    expectations["pda"] = pda
    evidence["checks"] = build_checks(evidence, expectations)
    return evidence


def decompress_lz4(compressed, target, limit=None):
    with open(target, "wb") as output:
        process = subprocess.Popen(
            ["lz4", "-d", "-c", compressed],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        remaining = limit
        try:
            while True:
                size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
                chunk = process.stdout.read(size)
                if not chunk:
                    break
                output.write(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
                    if remaining <= 0:
                        break
        finally:
            process.kill()
            process.wait()


def extract_member(member, source, target, read_limit=None, output_limit=None):
    if member.name.endswith(".lz4"):
        with tempfile.NamedTemporaryFile(delete=False) as temporary:
            if read_limit is None:
                shutil.copyfileobj(source, temporary)
            else:
                remaining = read_limit
                while remaining > 0:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    temporary.write(chunk)
                    remaining -= len(chunk)
            compressed = temporary.name
        try:
            decompress_lz4(compressed, target, output_limit)
        finally:
            os.unlink(compressed)
    else:
        with open(target, "wb") as output:
            if read_limit is None:
                shutil.copyfileobj(source, output)
            else:
                output.write(source.read(read_limit))


def extract_firmware(firmware, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    images = out_dir / "images"
    images.mkdir(exist_ok=True)

    archive = None
    if zipfile.is_zipfile(firmware):
        archive = zipfile.ZipFile(firmware)
        names = archive.namelist()
        ap_name = next(
            (name for name in names if re.search(r"(^|/)AP_.*\.tar(\.md5)?$", name)),
            None,
        )
        if not ap_name:
            raise SystemExit("no AP tar found in firmware zip")
        stream = archive.open(ap_name)
    else:
        stream = open(firmware, "rb")

    targets = set(BOOT_IMAGES + VBMETA_IMAGES + DTBO_IMAGES)
    matched = set()
    sample = []
    try:
        with tarfile.open(fileobj=stream, mode="r|", ignore_zeros=True) as tar:
            try:
                for member in tar:
                    if not member.isfile():
                        continue
                    base = Path(member.name).name
                    stem = base[:-4] if base.endswith(".lz4") else base
                    if len(sample) < 20:
                        sample.append(base)
                    if stem in targets:
                        with tar.extractfile(member) as source:
                            extract_member(member, source, images / stem)
                        matched.add(stem)
                    elif stem == "super.img":
                        compressed = base.endswith(".lz4")
                        with tar.extractfile(member) as source:
                            extract_member(
                                member,
                                source,
                                images / "super.prefix",
                                read_limit=8 * 1024 * 1024 if compressed else 1024 * 1024,
                                output_limit=2 * 1024 * 1024 if compressed else None,
                            )
                        matched.add(stem)
            except (tarfile.ReadError, EOFError) as error:
                print(f"warning: stopped reading AP tar: {error}", file=sys.stderr)
    finally:
        stream.close()
        if archive:
            archive.close()

    if not matched:
        print("AP tar members: " + ", ".join(sample), file=sys.stderr)
        raise SystemExit("no boot, vbmeta, super, or dtbo images found in AP tar")
    return images


def handle_matrix(args):
    history = {}
    for line in Path(args.history).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        csc = args.csc
        if "|" in line:
            csc, line = line.split("|", 1)
        parts = line.split("/")
        if len(parts) == 4:
            history.setdefault(parts[0], (csc, line))
    requested = [item.strip() for item in re.split(r"[,\n]", args.requested) if item.strip()]
    if not requested:
        requested = [pda for pda in ONE_UI_7_PDA if pda in history]
    include = []
    for item in requested:
        parts = item.split("/")
        if len(parts) == 4:
            include.append({"version": item, "pda": parts[0], "csc": args.csc})
        elif item in history:
            csc, version = history[item]
            include.append({"version": version, "pda": item, "csc": csc})
        else:
            raise SystemExit(
                f"{item} is not in the firmware history; known: "
                + ", ".join(sorted(history))
            )
    if not include:
        raise SystemExit("no firmware versions selected")
    print(json.dumps({"include": include}, indent=2))


def handle_extract(args):
    root = Path(__file__).resolve().parents[1]
    expectations = load_expectations(root)
    out_dir = Path(args.out)
    images = extract_firmware(Path(args.firmware), out_dir)
    evidence = inspect_images(images, args.model, args.csc, args.pda, expectations)
    evidence["expectations"] = dict(expectations, pda=args.pda)
    (out_dir / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    markdown = evidence_markdown(evidence, evidence["checks"])
    (out_dir / "evidence.md").write_text(markdown + "\n")
    print(markdown)
    failed = [check for check in evidence["checks"]
              if check["critical"] and not check["ok"]]
    if args.fail_on_mismatch and failed:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    matrix = subparsers.add_parser("matrix", help="build a GitHub Actions matrix")
    matrix.add_argument("--requested", default="")
    matrix.add_argument("--history", required=True)
    matrix.add_argument("--model", default="SM-X216B")
    matrix.add_argument("--csc", default="EGY")
    matrix.set_defaults(func=handle_matrix)

    extract = subparsers.add_parser("extract", help="extract and inspect an AP package")
    extract.add_argument("--firmware", required=True)
    extract.add_argument("--out", required=True)
    extract.add_argument("--model", default="SM-X216B")
    extract.add_argument("--csc", default="EGY")
    extract.add_argument("--pda", required=True)
    extract.add_argument("--fail-on-mismatch", action="store_true")
    extract.set_defaults(func=handle_extract)

    args = parser.parse_args()
    if args.command == "matrix":
        handle_matrix(args)
    else:
        handle_extract(args)


if __name__ == "__main__":
    main()
