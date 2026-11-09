#!/usr/bin/env python3
"""Offline Bitcoin private-key verifier. No network, files, logs, or key output."""
from __future__ import annotations

import getpass
import hashlib
import hmac
import sys

# secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", sha256(data)).digest()


def b58decode(text: str) -> bytes:
    value = 0
    for char in text:
        if char not in ALPHABET:
            raise ValueError("Not valid Base58")
        value = value * 58 + ALPHABET.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + raw


def b58encode(data: bytes) -> str:
    zeros = len(data) - len(data.lstrip(b"\x00"))
    value = int.from_bytes(data, "big")
    out = ""
    while value:
        value, rem = divmod(value, 58)
        out = ALPHABET[rem] + out
    return "1" * zeros + (out or ("" if zeros else "1"))


def b58check(payload: bytes) -> str:
    return b58encode(payload + sha256(sha256(payload))[:4])


def decode_wif(text: str, network: str) -> tuple[bytes, bool]:
    raw = b58decode(text.strip())
    if len(raw) not in (37, 38):
        raise ValueError("Invalid WIF length")
    payload, checksum = raw[:-4], raw[-4:]
    if not hmac.compare_digest(sha256(sha256(payload))[:4], checksum):
        raise ValueError("WIF checksum mismatch")
    expected_prefix = 0x80 if network == "mainnet" else 0xEF
    if payload[0] != expected_prefix:
        raise ValueError("WIF network prefix does not match selected network")
    compressed = len(payload) == 34 and payload[-1] == 0x01
    if len(payload) == 34 and not compressed:
        raise ValueError("Invalid compressed WIF marker")
    secret = payload[1:33]
    validate_secret(secret)
    return secret, compressed


def validate_secret(secret: bytes) -> None:
    if len(secret) != 32:
        raise ValueError("Private key must be exactly 32 bytes")
    scalar = int.from_bytes(secret, "big")
    if scalar < 1 or scalar >= N:
        raise ValueError("Private key scalar is outside the secp256k1 range")


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if a == b:
        slope = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def public_key(secret: bytes, compressed: bool) -> bytes:
    scalar = int.from_bytes(secret, "big")
    result, addend = None, G
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    if result is None:
        raise ValueError("Invalid public key")
    x, y = result
    if compressed:
        return bytes([2 | (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def bech32_polymod(values):
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i, gen in enumerate(generators):
            if (top >> i) & 1:
                chk ^= gen
    return chk


def convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise ValueError("Invalid data for Bech32 conversion")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid Bech32 padding")
    return ret


def segwit_address(program: bytes, network: str) -> str:
    hrp = "bc" if network == "mainnet" else "tb"
    data = [0] + convertbits(program, 8, 5)
    values = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp] + data
    polymod = bech32_polymod(values + [0] * 6) ^ 1  # witness v0 uses Bech32
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    return hrp + "1" + "".join(charset[d] for d in data + checksum)


def derive_addresses(secret: bytes, network: str, compressed: bool):
    pub = public_key(secret, compressed)
    pub_hash = hash160(pub)
    p2pkh_prefix = b"\x00" if network == "mainnet" else b"\x6f"
    p2sh_prefix = b"\x05" if network == "mainnet" else b"\xc4"
    results = {"P2PKH": b58check(p2pkh_prefix + pub_hash)}
    if compressed:
        redeem_script = b"\x00\x14" + pub_hash
        results["P2SH-P2WPKH"] = b58check(p2sh_prefix + hash160(redeem_script))
        results["P2WPKH"] = segwit_address(pub_hash, network)
    return results


def main():
    print("Bitcoin key verifier — OFFLINE / READ-ONLY")
    print("No blockchain lookup, balance check, file write, or network request is performed.")
    network = input("Network [mainnet/testnet] (default mainnet): ").strip().lower() or "mainnet"
    if network not in ("mainnet", "testnet"):
        print("Invalid network selection.")
        return 2

    kind = input("Key format [WIF/hex]: ").strip().lower()
    if kind not in ("wif", "hex"):
        print("Unsupported format.")
        return 2
    entered = getpass.getpass("Enter your private key (input is hidden): ").strip()
    try:
        if kind == "wif":
            secret, compressed = decode_wif(entered, network)
        else:
            value = entered.removeprefix("0x")
            if len(value) != 64:
                raise ValueError("Hex key must contain exactly 64 hexadecimal characters")
            try:
                secret = bytes.fromhex(value)
            except ValueError:
                raise ValueError("Hex key contains non-hexadecimal characters") from None
            validate_secret(secret)
            mode = input("Public key encoding [compressed/uncompressed] (default compressed): ").strip().lower()
            if mode not in ("", "compressed", "uncompressed"):
                raise ValueError("Invalid public key encoding")
            compressed = mode != "uncompressed"

        addresses = derive_addresses(secret, network, compressed)
        expected = input("Optional expected Bitcoin address (press Enter to skip): ").strip()
        print("\nDerived addresses:")
        matched = False
        for address_type, address in addresses.items():
            is_match = bool(expected) and hmac.compare_digest(address, expected)
            matched |= is_match
            print(f"{address_type}: {address}" + ("  <-- MATCH" if is_match else ""))
        if expected:
            print("\nRESULT: " + ("ADDRESS MATCH" if matched else "NO MATCH"))
        else:
            print("\nRESULT: Address derivation completed; no comparison was requested.")
        print("The entered key was not displayed or saved.")
        return 0
    except ValueError as exc:
        print(f"Input rejected: {exc}")
        return 2
    finally:
        # Best-effort reference cleanup; Python cannot guarantee memory zeroization.
        entered = ""
        secret = b""


if __name__ == "__main__":
    sys.exit(main())
