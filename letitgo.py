#!/usr/bin/env python3
"""
LetItGo - domain expiry hygiene checker

This tool checks one thing only:
which registrable domains are active, expiring soon, expired,
or could not be verified reliably.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

import requests
import tldextract
from dateutil import parser as date_parser

BANNER = r"""
                 .     *       .
       *        .     .        *
    .       _____________
         . /  LET IT GO /|
  *       /____________ / |
         |  expired    |  |
     .   |  domains    |  |
         |  can go     |  /
  *      |_____________|/

        release stale trust
"""


@dataclass
class Result:
    source: str
    input_name: str
    registrable_domain: str
    expiry_date: str
    days_left: str
    status: str
    notes: str


def normalize_domain(name: str) -> str:
    return name.strip().lower().rstrip(".")


def registrable_domain(name: str) -> Optional[str]:
    name = normalize_domain(name)
    if not name:
        return None
    extracted = tldextract.extract(name)
    if not extracted.domain or not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}"


def load_from_file(path: Path, csv_column: Optional[str] = None) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return rows
            column = csv_column or _guess_csv_column(reader.fieldnames)
            if not column:
                raise ValueError(
                    "Could not determine which CSV column contains hostnames/domains. "
                    "Use --csv-column."
                )
            for row in reader:
                value = (row.get(column) or "").strip()
                if value:
                    rows.append(("file:csv", value))
    else:
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                value = line.strip()
                if value and not value.startswith("#"):
                    rows.append(("file:text", value))
    return rows


def _guess_csv_column(fieldnames: Iterable[str]) -> Optional[str]:
    candidates = [name.strip() for name in fieldnames]
    preferred = ["domain", "hostname", "host", "fqdn", "name", "target"]
    lowered = {name.lower(): name for name in candidates}
    for item in preferred:
        if item in lowered:
            return lowered[item]
    return candidates[0] if candidates else None


def rdap_expiry(domain: str, timeout: int = 15) -> tuple[Optional[datetime], str]:
    url = f"https://rdap.org/domain/{domain}"
    try:
        response = requests.get(
            url,
            headers={"Accept": "application/rdap+json"},
            timeout=timeout,
        )
        if response.status_code >= 400:
            return None, f"RDAP HTTP {response.status_code}"
        data = response.json()
    except Exception as exc:
        return None, f"RDAP request failed: {exc}"

    events = data.get("events", [])
    for event in events:
        action = (event.get("eventAction") or "").lower()
        date_value = event.get("eventDate")
        if action in {"expiration", "expiry", "expiration date", "expires"} and date_value:
            try:
                parsed = date_parser.parse(date_value)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed, "RDAP"
            except Exception:
                continue

    notices = data.get("notices", [])
    if notices:
        return None, "RDAP returned data without usable expiration event"
    return None, "RDAP returned no usable expiration event"


def whois_expiry(domain: str, timeout: int = 20) -> tuple[Optional[datetime], str]:
    try:
        output = subprocess.check_output(
            ["whois", domain],
            stderr=subprocess.STDOUT,
            timeout=timeout,
        ).decode("utf-8", errors="ignore")
    except Exception as exc:
        return None, f"whois failed: {exc}"

    lines = output.splitlines()
    hits = ("expir", "renew", "paid-till", "registry expiry", "valid")
    for line in lines:
        lowered = line.lower()
        if any(token in lowered for token in hits) and ":" in line:
            value = line.split(":", 1)[1].strip()
            try:
                parsed = date_parser.parse(value)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed, "WHOIS"
            except Exception:
                continue

    return None, "WHOIS returned no usable expiration field"


def evaluate_domain(source: str, input_name: str, warn_days: int) -> Result:
    reg = registrable_domain(input_name)
    if not reg:
        return Result(
            source=source,
            input_name=input_name,
            registrable_domain="",
            expiry_date="",
            days_left="",
            status="not_registrable",
            notes="Input does not look like a registrable public domain",
        )

    expiry_dt, method_note = rdap_expiry(reg)
    if expiry_dt is None:
        expiry_dt, whois_note = whois_expiry(reg)
        method_note = f"{method_note}; {whois_note}"

    if expiry_dt is None:
        return Result(
            source=source,
            input_name=input_name,
            registrable_domain=reg,
            expiry_date="",
            days_left="",
            status="unknown",
            notes=method_note,
        )

    now = datetime.now(timezone.utc)
    days_left = (expiry_dt - now).days

    if days_left < 0:
        status = "expired"
    elif days_left <= warn_days:
        status = "expiring_soon"
    else:
        status = "active"

    return Result(
        source=source,
        input_name=input_name,
        registrable_domain=reg,
        expiry_date=expiry_dt.date().isoformat(),
        days_left=str(days_left),
        status=status,
        notes=method_note,
    )


def print_table(results: list[Result]) -> None:
    headers = ["status", "days_left", "registrable_domain", "input_name"]
    rows = [[r.status, r.days_left, r.registrable_domain, r.input_name] for r in results]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        print("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))


def write_csv(path: Path, results: list[Result]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "source",
                "input_name",
                "registrable_domain",
                "expiry_date",
                "days_left",
                "status",
                "notes",
            ],
        )
        writer.writeheader()
        for result in results:
            writer.writerow(result.__dict__)


def write_json(path: Path, results: list[Result]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump([r.__dict__ for r in results], f, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check registrable domains for expiry status.",
    )
    parser.add_argument("--from-file", required=True, help="Path to a .txt or .csv file containing domains/hostnames")
    parser.add_argument("--csv-column", help="CSV column to read when input is a CSV file")
    parser.add_argument("--warn-days", type=int, default=30, help="Mark domains within this many days as expiring_soon")
    parser.add_argument("--output", default="results.csv", help="CSV output path")
    parser.add_argument("--json-output", help="Optional JSON output path")
    parser.add_argument("--no-banner", action="store_true", help="Do not print the banner")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)
        print()

    input_path = Path(args.from_file)
    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        raw_items = load_from_file(input_path, args.csv_column)
    except Exception as exc:
        print(f"Failed to load input: {exc}", file=sys.stderr)
        return 1

    if not raw_items:
        print("No domains found in input.", file=sys.stderr)
        return 1

    deduped: dict[str, tuple[str, str]] = {}
    for source, value in raw_items:
        key = normalize_domain(value)
        if key and key not in deduped:
            deduped[key] = (source, value)

    results = [evaluate_domain(source, value, args.warn_days) for source, value in deduped.values()]
    results.sort(key=lambda r: (r.status, r.days_left if r.days_left else "999999", r.registrable_domain))

    print_table(results)
    write_csv(Path(args.output), results)
    if args.json_output:
        write_json(Path(args.json_output), results)

    print()
    print(f"Wrote CSV report to: {args.output}")
    if args.json_output:
        print(f"Wrote JSON report to: {args.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
