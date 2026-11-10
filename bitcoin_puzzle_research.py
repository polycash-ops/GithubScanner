#!/usr/bin/env python3
"""Public-data research for Bitcoin Puzzle #71.

This utility validates a Base58Check P2PKH address and reconciles *reported*
inclusive keyspace intervals. It never generates, tests, derives, stores, or
prints private-key candidates. Reported ranges are claims, not proof of work.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

TARGET_ADDRESS = "1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU"
RANGE_START = 0x400000000000000000
RANGE_END = 0x7FFFFFFFFFFFFFFFFF  # inclusive


def b58decode(text: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    if not text:
        raise ValueError("empty Base58 string")
    number = 0
    for char in text:
        if char not in alphabet:
            raise ValueError(f"invalid Base58 character: {char!r}")
        number = number * 58 + alphabet.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + raw


def decode_p2pkh_address(address: str) -> dict[str, str]:
    decoded = b58decode(address)
    if len(decoded) != 25:
        raise ValueError(f"expected 25 decoded bytes, got {len(decoded)}")
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError("Base58Check checksum mismatch")
    if payload[0] != 0x00:
        raise ValueError(f"not a mainnet P2PKH address (version 0x{payload[0]:02x})")
    return {"address": address, "version": "00", "hash160": payload[1:].hex()}


def parse_hex(value: Any, field: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a hex string")
    cleaned = value.lower().removeprefix("0x")
    if not cleaned or any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError(f"{field} is not valid hexadecimal")
    return int(cleaned, 16)


def normalize_ranges(records: list[dict[str, Any]]) -> list[tuple[int, int]]:
    intervals: list[tuple[int, int]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"range record {index} must be an object")
        start = parse_hex(record.get("start"), f"ranges[{index}].start")
        end = parse_hex(record.get("end"), f"ranges[{index}].end")
        if start < RANGE_START or end > RANGE_END or start > end:
            raise ValueError(f"range record {index} is outside Puzzle #71 bounds or reversed")
        intervals.append((start, end))
    intervals.sort()
    merged: list[list[int]] = []
    for start, end in intervals:
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [(start, end) for start, end in merged]


def summarize(records: list[dict[str, Any]]) -> dict[str, Any]:
    merged = normalize_ranges(records)
    total = RANGE_END - RANGE_START + 1
    covered = sum(end - start + 1 for start, end in merged)
    gaps: list[tuple[int, int]] = []
    cursor = RANGE_START
    for start, end in merged:
        if cursor < start:
            gaps.append((cursor, start - 1))
        cursor = end + 1
    if cursor <= RANGE_END:
        gaps.append((cursor, RANGE_END))
    return {
        "target": TARGET_ADDRESS,
        "range_start": f"{RANGE_START:018x}",
        "range_end_inclusive": f"{RANGE_END:018x}",
        "reported_covered_candidates": covered,
        "total_candidates": total,
        "reported_coverage_percent": round(covered * 100 / total, 12),
        "merged_reported_ranges": [{"start": f"{a:x}", "end": f"{b:x}"} for a, b in merged],
        "unreported_ranges": [{"start": f"{a:x}", "end": f"{b:x}"} for a, b in gaps],
        "evidence_warning": "Coverage is based only on supplied reports. It is not independently verified or cryptographic proof of completed work.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", default=TARGET_ADDRESS, help="public Bitcoin address to validate")
    parser.add_argument("--ranges", type=Path, help="JSON file containing a top-level 'ranges' array")
    args = parser.parse_args()

    result: dict[str, Any] = {"address_check": decode_p2pkh_address(args.address)}
    if args.ranges:
        data = json.loads(args.ranges.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("ranges"), list):
            raise ValueError("input JSON must contain a 'ranges' array")
        result["progress"] = summarize(data["ranges"])
    else:
        result["progress"] = summarize([])
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
