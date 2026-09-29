"""Deterministic identifier extraction from raw evidence.

Everything in this module is regex/rule based and fully reproducible: the same
input text always yields the same identifiers, which is a precondition for
evidence reproducibility in court.

Implemented extractors
---------------------
* Bitcoin addresses - Base58Check (P2PKH/P2SH) and Bech32/Bech32m (P2WPKH/
  P2WSH), with full checksum verification for Base58.
* PGP public keys    - armored blocks dearmored to raw key bytes, then fingerprinted
  as canonical 40-char uppercase hex (SHA-1 of the key, matching ``gpg``).
* Onion addresses    - v3 (56 base32 chars) and legacy v2 (16 chars).
* Handles            - Discord, Telegram, Session IDs, e-mail, clearnet IPs.
"""

from __future__ import annotations

import base64
import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

# ---------------------------------------------------------------------------
# Bitcoin
# ---------------------------------------------------------------------------

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BTC_BECH32_RE = re.compile(
    r"\b(?:bc1)[023456789acdefghjklmnpqrstuvwxyz]{11,71}\b", re.IGNORECASE
)
_BTC_BASE58_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58check_valid(address: str) -> bool:
    """Verify the 4-byte Base58Check checksum (double SHA-256)."""
    # Base58 decode by hand to avoid a hard dependency on a bitcoin library.
    num = 0
    for char in address:
        index = _BASE58_ALPHABET.find(char)
        if index < 0:
            return False
        num = num * 58 + index
    decoded = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    decoded = b"\x00" * (len(address) - len(address.lstrip("1"))) + decoded
    if len(decoded) != 25:
        return False
    import hashlib

    payload, checksum = decoded[:21], decoded[21:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


def _bech32_valid(address: str) -> bool:
    """Verify the Bech32/Bech32m checksum and version-appropriate length."""
    if any(ord(c) < 33 or ord(c) > 126 for c in address):
        return False
    if address.lower() != address and address.upper() != address:
        return False
    address = address.lower()
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address) or len(address) > 90:
        return False

    def polymod(values: Iterable[int]) -> int:
        generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = ((chk & 0x1FFFFFF) << 5) ^ value
            for i in range(5):
                chk ^= generator[i] if ((top >> i) & 1) else 0
        return chk

    # Expand the human-readable part to 5-bit groups for the checksum.
    hrp_values = [ord(c) >> 5 for c in address[:pos]] + [0] + [ord(c) & 31 for c in address[:pos]]

    data = [_BECH32_CHARSET.find(c) for c in address[pos + 1:]]
    if any(d < 0 for d in data):
        return False

    witver = data[0]
    encoding_const = 1 if witver == 0 else 0x2BC830A3
    if polymod(hrp_values + data) != encoding_const:
        return False

    program = _convertbits(data[1:-6], 5, 8, False)
    if program is None:
        return False
    length = len(program)
    if witver == 0 and length not in (20, 32):
        return False
    if witver > 16 or (witver > 0 and length not in (2, 40)):
        return False
    return True


def _convertbits(
    data: Iterable[int], frombits: int, tobits: int, pad: bool = True
) -> Optional[list[int]]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def extract_bitcoin_addresses(text: str) -> list[dict[str, Any]]:
    """Return checksum-validated Bitcoin addresses with their encoding."""
    results: dict[str, dict[str, Any]] = {}

    for match in _BTC_BECH32_RE.findall(text):
        candidate = match.lower()
        if not _bech32_valid(candidate):
            continue
        results[candidate] = {
            "value": candidate,
            "encoding": "bech32",
            "witness_version": 0 if candidate[3] == "q" else int(_BECH32_CHARSET.find(candidate[3])),
        }

    for match in _BTC_BASE58_RE.findall(text):
        if not _base58check_valid(match):
            continue
        results[match] = {
            "value": match,
            "encoding": "base58check",
            "script_type": "p2pkh" if match.startswith("1") else "p2sh",
        }

    # Preserve first-seen order for deterministic output.
    ordered = sorted(results.values(), key=lambda item: text.find(item["value"]))
    return ordered


# ---------------------------------------------------------------------------
# PGP
# ---------------------------------------------------------------------------

_PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)
_PGP_PUBKEY_PACKET_RE = re.compile(
    rb"\x99[\x01\x02]", re.DOTALL
)


def dearmor_pgp_block(armored: str) -> Optional[bytes]:
    """Strip the ASCII armor and CRC24, returning the raw OpenPGP packet stream."""
    payload_lines: list[str] = []
    inside = False
    for raw_line in armored.splitlines():
        line = raw_line.rstrip("\r\n")
        if line.startswith("-----BEGIN"):
            inside = True
            continue
        if line.startswith("-----END"):
            inside = False
            break
        if not inside:
            continue
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("="):  # CRC24 checksum line
            break
        if ":" in stripped and not stripped.endswith("="):
            # Armor headers such as "Version: GnuPG v2"
            if stripped.split(":", 1)[0].isalpha() and " " not in stripped.split(":", 1)[0]:
                continue
        payload_lines.append(stripped)

    if not payload_lines:
        return None
    try:
        return base64.b64decode("".join(payload_lines), validate=False)
    except Exception:
        return None


def _pgp_fingerprint(key_bytes: bytes) -> Optional[str]:
    """Canonical 40-char uppercase hex fingerprint of the first public key packet."""
    # Walk packets to the first tag-6 (public key) and hash its body per RFC 4880.
    offset = 0
    while offset < len(key_bytes):
        tag_byte = key_bytes[offset]
        if not tag_byte & 0x80:
            break
        if tag_byte & 0x40:  # new format
            offset += 1
            if offset >= len(key_bytes):
                break
            tag = tag_byte & 0x3F
            first_len = key_bytes[offset]
            if first_len < 192:
                length = first_len
                offset += 1
            elif first_len < 224:
                length = ((first_len - 192) << 8) + key_bytes[offset + 1] + 192
                offset += 2
            elif first_len == 255:
                length = int.from_bytes(key_bytes[offset + 1: offset + 5], "big")
                offset += 5
            else:
                return None
        else:  # old format
            tag = (tag_byte >> 2) & 0x0F
            length_type = tag_byte & 0x03
            offset += 1
            if length_type == 0:
                length = key_bytes[offset]
                offset += 1
            elif length_type == 1:
                length = int.from_bytes(key_bytes[offset: offset + 2], "big")
                offset += 2
            elif length_type == 2:
                length = int.from_bytes(key_bytes[offset: offset + 4], "big")
                offset += 4
            else:
                length = len(key_bytes) - offset

        if tag == 6:
            body = key_bytes[offset: offset + length]
            if len(body) < 6:
                return None
            import hashlib

            version = body[0]
            # v4 fingerprints hash the packet body prefixed with 0x99 + 2-byte length.
            material = b"\x99" + len(body).to_bytes(2, "big") + body if version == 4 else body
            return hashlib.sha1(material).hexdigest().upper()

        offset += length

    return None


_FINGERPRINT_RE = re.compile(r"\b(?:0x)?([0-9A-Fa-f]{40})\b")
_FINGERPRINT_LABEL_RE = re.compile(
    r"(?:pgp|fingerprint|key\s*id|fpr)\b[^\n]{0,24}?([0-9A-Fa-f]{16,40})",
    re.IGNORECASE,
)
_FINGERPRINT_LABELLED = re.compile(
    r"(?:pgp|fingerprint|fpr|key\s*id)\b[^\n]{0,24}?\b(?:0x)?[0-9A-Fa-f]{16,40}\b",
    re.IGNORECASE,
)


def _is_probable_fingerprint(token: str) -> bool:
    """Reject hex runs that are obviously not OpenPGP fingerprints.

    A 40-character hex string is only a fingerprint if it has a realistic mix
    of digit and letter characters. All-digit or all-letter runs are almost
    always digests, serials, session identifiers, or padding rather than a key
    an actor chose to publish.
    """
    if len(token) != 40:
        return False
    digits = sum(character.isdigit() for character in token)
    return 8 <= digits <= 32


def extract_pgp_keys(text: str) -> list[dict[str, Any]]:
    """Extract PGP fingerprints from armored key blocks and from bare hex.

    Armored blocks are the authoritative source: the fingerprint is computed
    from the key packet rather than read out of the surrounding prose. Most
    operational posts, however, advertise only a fingerprint in text form
    ("pgp: 2256F280..."), so labelled and standalone 40-hex tokens are accepted
    as lower-confidence claims. Armored results always win over a bare match of
    the same fingerprint.
    """
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    for armored in _PGP_BLOCK_RE.findall(text):
        full = f"-----BEGIN PGP PUBLIC KEY BLOCK-----{armored}-----END PGP PUBLIC KEY BLOCK-----"
        raw = dearmor_pgp_block(full)
        if raw is None:
            continue
        fingerprint = _pgp_fingerprint(raw)
        if fingerprint is None or fingerprint in seen:
            continue
        seen.add(fingerprint)
        results.append(
            {
                "fingerprint": fingerprint,
                "key_bytes": len(raw),
                "key_id": fingerprint[-16:],
                "algorithm": "rsa/dsa/ecdsa (opaque)",
            }
        )

    for match in _FINGERPRINT_RE.finditer(text):
        token = match.group(1).upper()
        if token in seen or not _is_probable_fingerprint(token):
            continue
        # A token sitting under a "pgp:"/"fingerprint:" label is an explicit
        # claim; a bare one is only a likely claim, so confidence is lower.
        labelled = _FINGERPRINT_LABELLED.search(text, max(0, match.start() - 32), match.end())
        seen.add(token)
        results.append(
            {
                "fingerprint": token,
                "key_bytes": 0,
                "key_id": token[-16:],
                "algorithm": "unknown (advertised fingerprint)",
                "source": "labelled-text" if labelled else "bare-text",
                "confidence": 0.90 if labelled else 0.70,
            }
        )

    return results


# ---------------------------------------------------------------------------
# Onion / clearnet
# ---------------------------------------------------------------------------

_ONION_V3_RE = re.compile(r"\b[a-z2-7]{56}\.onion\b", re.IGNORECASE)
_ONION_V2_RE = re.compile(r"\b[a-z2-7]{16}\.onion\b", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)


def extract_onion_addresses(text: str) -> list[dict[str, Any]]:
    """Extract v3 (preferred) and legacy v2 onion hostnames."""
    results: dict[str, dict[str, Any]] = {}
    for match in _ONION_V3_RE.findall(text):
        host = match.lower()
        results[host] = {"value": host, "onion_version": 3, "key_id": host.split(".")[0][:16]}
    for match in _ONION_V2_RE.findall(text):
        host = match.lower()
        results.setdefault(host, {"value": host, "onion_version": 2, "key_id": host.split(".")[0]})
    return sorted(results.values(), key=lambda item: text.lower().find(item["value"]))


def extract_clearnet_ips(text: str) -> list[dict[str, Any]]:
    """Extract IPv4 literals, flagging RFC1918 space separately."""
    import ipaddress

    results: list[dict[str, Any]] = []
    for match in set(_IPV4_RE.findall(text)):
        try:
            addr = ipaddress.IPv4Address(match)
        except ValueError:
            continue
        if match.startswith("0.") or match.endswith(".255"):
            continue
        results.append(
            {
                "value": match,
                "is_private": addr.is_private,
                "is_reserved": addr.is_reserved,
                "scope": "internal" if addr.is_private else "public",
            }
        )
    return sorted(results, key=lambda item: text.find(item["value"]))


# ---------------------------------------------------------------------------
# Handles
# ---------------------------------------------------------------------------

_DISCORD_RE = re.compile(r"\b(?:discord(?:app)?\.com/users/|#|@)?([A-Za-z0-9_.\-]{2,32})\b(?=\s|$)")
_TELEGRAM_RE = re.compile(r"(?:t\.me/|telegram\.me/)?@([A-Za-z0-9_]{5,32})\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_SESSION_RE = re.compile(r"\bsession[_\- ]?id[:= ]+([A-Za-z0-9\-]{16,64})\b", re.IGNORECASE)

_HANDLE_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "have", "will", "your",
    "http", "https", "www", "com", "html", "index", "price", "notes", "handle",
    "wallet", "contact", "vendor", "listing", "posted", "vendor-listing", "title",
    "keyboard", "polynomial", "merchant", "escrow", "delivery", "buyer", "vendor-listing",
}


def extract_handles(text: str) -> list[dict[str, Any]]:
    """Extract communication identifiers with their platform provenance."""
    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def _add(platform: str, handle: str, confidence: float) -> None:
        handle = handle.strip()
        if not handle or handle.lower() in _HANDLE_STOPWORDS:
            return
        if len(handle) < 3 or len(handle) > 64:
            return
        key = (platform, handle.lower())
        if key in seen:
            return
        seen.add(key)
        results.append(
            {"value": handle, "platform": platform, "confidence": confidence}
        )

    for handle in _TELEGRAM_RE.findall(text):
        _add("TELEGRAM", handle, 0.90)

    for match in re.finditer(r"discord(?:app)?\.com/users/([A-Za-z0-9]{2,32})", text, re.I):
        _add("DISCORD", match.group(1), 0.95)
    for match in re.finditer(r"(?:^|\s)#([A-Za-z0-9_.\-]{2,32})(?=\s|$)", text):
        _add("DISCORD", match.group(1), 0.75)

    for address in _EMAIL_RE.findall(text):
        _add("EMAIL", address, 0.95)

    for session_id in _SESSION_RE.findall(text):
        _add("SESSION_ID", session_id, 0.85)

    # Bare @handles not already captured as Telegram.
    for handle in re.findall(r"(?<![A-Za-z0-9])@([A-Za-z0-9_]{4,32})\b", text):
        _add("TELEGRAM", handle, 0.60)

    return sorted(results, key=lambda item: text.find(item["value"]))


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------


@dataclass
class ExtractionResult:
    """Structured output of a full extraction pass."""

    bitcoin: list[dict[str, Any]] = field(default_factory=list)
    pgp: list[dict[str, Any]] = field(default_factory=list)
    onion: list[dict[str, Any]] = field(default_factory=list)
    clearnet_ips: list[dict[str, Any]] = field(default_factory=list)
    handles: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            len(self.bitcoin)
            + len(self.pgp)
            + len(self.onion)
            + len(self.clearnet_ips)
            + len(self.handles)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "btc_wallets": self.bitcoin,
            "pgp_keys": self.pgp,
            "onion_domains": self.onion,
            "clearnet_ips": self.clearnet_ips,
            "handles": self.handles,
            "total_identifiers": self.total,
        }


def extract_all(text: str) -> ExtractionResult:
    """Run every deterministic extractor over ``text``."""
    if not text:
        return ExtractionResult()
    return ExtractionResult(
        bitcoin=extract_bitcoin_addresses(text),
        pgp=extract_pgp_keys(text),
        onion=extract_onion_addresses(text),
        clearnet_ips=extract_clearnet_ips(text),
        handles=extract_handles(text),
    )


__all__ = [
    "ExtractionResult",
    "extract_all",
    "extract_bitcoin_addresses",
    "extract_pgp_keys",
    "extract_onion_addresses",
    "extract_clearnet_ips",
    "extract_handles",
    "dearmor_pgp_block",
    "dt",
]
