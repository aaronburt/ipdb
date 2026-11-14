#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import ipaddress
import json
import re
import shutil
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

CONTINENTS = {"AF", "AN", "AS", "EU", "NA", "OC", "SA"}
CC_RE = re.compile(r"^[A-Z]{2}$")
SKIP_CODES = {"ZZ", "XX"}
OUTPUT_DIRS = ("lists", "nginx", "traefik", "ipset", "nft")
HEADER_COUNTRY_COLUMNS = ("country_code", "country", "countrycode")

ATTRIBUTION = (
    "Contains data from IP to Country Lite by DB-IP.com (https://db-ip.com), "
    "licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). "
    "Modified: IP ranges merged, converted to CIDR blocks and grouped by country."
)
ATTRIBUTION_FILE = "IP Geolocation by DB-IP (https://db-ip.com)\n\n" + ATTRIBUTION + "\n"
FAMILIES = ((4, "inet", "ipv4_addr"), (6, "inet6", "ipv6_addr"))


def open_text(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return open(path, "rt", encoding="utf-8", newline="")


def country_index(row: list[str], header: list[str] | None, lineno: int) -> int:
    if header is not None:
        for name in HEADER_COUNTRY_COLUMNS:
            if name in header:
                return header.index(name)
        raise ValueError(f"header has no country column: {header!r}")
    if len(row) == 3:
        return 2
    if len(row) > 3 and row[2] in CONTINENTS:
        for i in range(3, len(row)):
            if CC_RE.match(row[i].upper()):
                return i
    raise ValueError(f"line {lineno}: cannot tell which column is the country code: {row!r}")


def read_ranges(path: Path):
    header = None
    seen_data = False
    with open_text(path) as fh:
        for lineno, raw in enumerate(csv.reader(fh), 1):
            row = [c.strip() for c in raw]
            if not any(row):
                continue
            try:
                start = ipaddress.ip_address(row[0])
                end = ipaddress.ip_address(row[1])
            except (ValueError, IndexError):
                if not seen_data and header is None:
                    header = [c.lower() for c in row]
                    continue
                raise ValueError(f"line {lineno}: bad address in {row!r}") from None
            seen_data = True
            if start.version != end.version or start > end:
                raise ValueError(f"line {lineno}: bad range {start}-{end}")
            cc = row[country_index(row, header, lineno)].upper()
            if not CC_RE.match(cc):
                raise ValueError(f"line {lineno}: bad country code {cc!r}")
            yield start.version, int(start), int(end), cc


def merge(ranges):
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def to_cidrs(merged, version: int):
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    nets = []
    for start, end in merged:
        nets.extend(ipaddress.summarize_address_range(cls(start), cls(end)))
    return nets


def count_conflicts(ranges) -> int:
    conflicts = 0
    top, top_cc = -1, None
    for start, end, cc in sorted(ranges):
        if start <= top and cc != top_cc:
            conflicts += 1
        if end > top:
            top, top_cc = end, cc
    return conflicts


def build(path: Path, allow_overlap: bool = False):
    per_country = defaultdict(lambda: {4: [], 6: []})
    by_family = {4: [], 6: []}
    rows = 0
    for version, start, end, cc in read_ranges(path):
        rows += 1
        if cc in SKIP_CODES:
            continue
        per_country[cc][version].append((start, end))
        by_family[version].append((start, end, cc))
    if rows == 0:
        raise ValueError(f"no data rows found in {path}")

    overlaps = sum(count_conflicts(by_family[v]) for v in (4, 6))
    if overlaps and not allow_overlap:
        raise ValueError(f"{overlaps} ranges overlap a different country; refusing (use --allow-overlap)")

    data = {
        cc: {v: to_cidrs(merge(per_country[cc][v]), v) for v in (4, 6)}
        for cc in sorted(per_country)
    }
    return data, {"rows": rows, "overlaps": overlaps}


def write_lines(path: Path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def header(prefix: str = "#"):
    return [f"{prefix} {ATTRIBUTION}"]


def write_plain(out: Path, cc: str, nets: dict[int, list[str]]):
    for version in (4, 6):
        if nets[version]:
            write_lines(out / f"lists/v{version}/{cc}.txt", nets[version])
    write_lines(out / f"lists/all/{cc}.txt", nets[4] + nets[6])


def write_nginx(out: Path, cc: str, cidrs: list[str]):
    write_lines(out / f"nginx/allow/{cc}.conf", header() + [f"allow {c};" for c in cidrs])
    write_lines(out / f"nginx/deny/{cc}.conf", header() + [f"deny {c};" for c in cidrs])


def write_traefik(out: Path, cc: str, cidrs: list[str]):
    lines = header() + [
        "http:",
        "  middlewares:",
        f"    geo-allow-{cc.lower()}:",
        "      ipAllowList:",
        "        sourceRange:",
    ]
    write_lines(out / f"traefik/{cc}.yml", lines + [f'          - "{c}"' for c in cidrs])


def write_firewall(out: Path, cc: str, nets: dict[int, list[str]]):
    low = cc.lower()
    for version, family, addr_type in FAMILIES:
        cidrs = nets[version]
        if not cidrs:
            continue
        name = f"geo-{low}-v{version}"
        maxelem = max(65536, 1 << (len(cidrs) - 1).bit_length())
        write_lines(
            out / f"ipset/{cc}.v{version}.ipset",
            header()
            + [f"create {name} hash:net family {family} maxelem {maxelem} -exist", f"flush {name}"]
            + [f"add {name} {c} -exist" for c in cidrs],
        )
        set_name = f"{low}_v{version}"
        write_lines(
            out / f"nft/{cc}.v{version}.nft",
            header()
            + [
                "add table inet geo",
                f"add set inet geo {set_name} {{ type {addr_type}; flags interval; auto-merge; }}",
                f"flush set inet geo {set_name}",
                f"add element inet geo {set_name} {{",
                ",\n".join(f"  {c}" for c in cidrs),
                "}",
            ],
        )


def write_outputs(data, out: Path):
    for name in OUTPUT_DIRS:
        shutil.rmtree(out / name, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)

    geo_map = []
    for cc, families in data.items():
        nets = {v: [str(n) for n in families[v]] for v in (4, 6)}
        cidrs = nets[4] + nets[6]
        if not cidrs:
            continue
        write_plain(out, cc, nets)
        write_nginx(out, cc, cidrs)
        write_traefik(out, cc, cidrs)
        write_firewall(out, cc, nets)
        geo_map.extend(f"    {c} {cc};" for c in cidrs)

    write_lines(out / "nginx/geo-country.conf", header() + ["geo $geo_country {", "    default ZZ;"] + geo_map + ["}"])
    for path in (out / "ATTRIBUTION.txt", out / "lists/ATTRIBUTION.txt"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(ATTRIBUTION_FILE, encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def output_files(out: Path):
    return sorted(
        p for p in out.rglob("*")
        if p.is_file() and ".git" not in p.parts and p.suffix != ".sha256" and p.name != "SHA256SUMS"
    )


def write_checksums(out: Path):
    sums = []
    for path in output_files(out):
        digest = sha256_file(path)
        rel = path.relative_to(out).as_posix()
        sums.append(f"{digest}  {rel}")
        path.with_name(path.name + ".sha256").write_text(f"{digest}  {path.name}\n", encoding="utf-8")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def write_manifest(data, out: Path, src: Path, source_url: str, stats, generated_at: str):
    files = {p.relative_to(out).as_posix(): sha256_file(p) for p in output_files(out) if p.name != "manifest.json"}
    manifest = {
        "attribution": ATTRIBUTION,
        "source": {
            "name": "DB-IP IP to Country Lite",
            "url": source_url,
            "file": src.name,
            "sha256": sha256_file(src),
            "rows": stats["rows"],
        },
        "generated_at": generated_at,
        "countries": {cc: {"v4_cidrs": len(f[4]), "v6_cidrs": len(f[6])} for cc, f in data.items()},
        "files": files,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def parse_args(argv):
    p = argparse.ArgumentParser(description="Generate per-country CIDR lists from DB-IP IP to Country Lite.")
    p.add_argument("--input", required=True, type=Path, help="DB-IP country CSV (.csv or .csv.gz)")
    p.add_argument("--out", required=True, type=Path, help="output directory")
    p.add_argument("--source-url", default="", help="recorded in manifest.json")
    p.add_argument("--min-countries", type=int, default=150, help="fail if fewer countries are found")
    p.add_argument("--allow-overlap", action="store_true", help="continue when ranges overlap across countries")
    p.add_argument("--generated-at", default=None, help="override the manifest timestamp")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        data, stats = build(args.input, args.allow_overlap)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if len(data) < args.min_countries:
        print(f"error: only {len(data)} countries found (min {args.min_countries}); refusing to write", file=sys.stderr)
        return 1
    write_outputs(data, args.out)
    generated_at = args.generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_manifest(data, args.out, args.input, args.source_url, stats, generated_at)
    write_checksums(args.out)
    print(f"wrote {len(data)} countries from {stats['rows']} rows to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
