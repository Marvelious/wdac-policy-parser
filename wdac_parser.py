#!/usr/bin/env python3
"""
WDAC Binary Policy Parser — Python implementation.

Parses Windows Defender Application Control (.cip / .p7b) binary policies
into structured data. First Python implementation of this format.

Based on mattifestation/WDACTools (PowerShell).
"""

import argparse
import struct
import uuid
from dataclasses import dataclass, field
from typing import Optional

from wdac_xml import serialize_policy


# ── Known constants ──────────────────────────────────────────────────────────

KNOWN_EKUS = {
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
    "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
    "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Quality Labs (WHQL Crypto)",
    "1.3.6.1.4.1.311.61.4.1": "Early Launch Anti-malware Driver",
    "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
    "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
    "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
    "1.3.6.1.4.1.311.10.3.24": "Windows TCB Component",
    "1.3.6.1.4.1.311.10.3.25": "Windows Store",
    "1.3.6.1.4.1.311.76.3.1": "Microsoft Store",
}

POLICY_TYPE_NAMES = {
    "a244370e-44c2-4e32-add3-f73c2d7b5835": "Enterprise",
    "d2bda982-ccf6-4344-ac5b-0b44427b6816": "Revoke",
    "976d12c8-cb9f-4730-be52-54600843238e": "SKU",
    "ee15cf2f-e058-4499-b63c-e5508e75b56e": "WindowsLockdown",
    "2a5a0136-f09f-498e-99cc-51099011157c": "ATP",
    "3e3a8ad3-7966-4c69-bc48-d2de5c7a584b": "Driver",
}

# Option flags — from CodeIntegrity.PolicyRules enum in WDACTools
OPTION_FLAGS = {
    0x00000004: "Enabled:UMCI",
    0x00000008: "Enabled:Boot Menu Protection",
    0x00000010: "Enabled:Intelligent Security Graph Authorization",
    0x00000020: "Enabled:Invalidate EAs on Reboot",
    0x00000040: "Enabled:Windows Lockdown Trial Mode",
    0x00000080: "Required:WHQL",
    0x00000100: "Enabled:Developer Mode Dynamic Code Trust",
    0x00000400: "Enabled:Allow Supplemental Policies",
    0x00000800: "Disabled:Runtime FilePath Rule Protection",
    0x00002000: "Enabled:Revoked Expired As Unsigned",
    0x00010000: "Enabled:Audit Mode",
    0x00020000: "Disabled:Flight Signing",
    0x00040000: "Enabled:Inherit Default Policy",
    0x00080000: "Enabled:Unsigned System Integrity Policy",
    0x00100000: "Enabled:Dynamic Code Security",
    0x00200000: "Required:EV Signers",
    0x00400000: "Enabled:Boot Audit on Failure",
    0x00800000: "Enabled:Advanced Boot Options Menu",
    0x01000000: "Disabled:Script Enforcement",
    0x02000000: "Required:Enforce Store Applications",
    0x04000000: "Enabled:Secure Setting Policy",
    0x08000000: "Enabled:Managed Installer",
    0x10000000: "Enabled:Update Policy No Reboot",
    0x20000000: "Enabled:Conditional Windows Lockdown Policy",
}

HASH_ALGO_NAMES = {
    0x0000: "None",
    0x8001: "MD5",
    0x8003: "MD5",
    0x8004: "SHA1",
    0x800C: "SHA256",
    0x800D: "SHA384",
    0x800E: "SHA512",
}


# ── Data structures ──────────────────────────────────────────────────────────

@dataclass
class EKURule:
    oid: str
    friendly_name: str
    raw_bytes: bytes = field(default_factory=bytes, repr=False)


@dataclass
class FileRule:
    rule_type: int        # 0=Deny, 1=Allow, 2=FileAttrib
    file_name: str
    min_version: str
    hash_value: bytes = field(default_factory=bytes, repr=False)
    # V3+ extensions
    max_version: str = ""
    app_ids: str = ""
    # V4+
    internal_name: str = ""
    file_description: str = ""
    product_name: str = ""
    # V5+
    package_family_name: str = ""
    package_version: str = ""
    # V7+
    file_path: str = ""

    @property
    def type_name(self) -> str:
        return {0: "Deny", 1: "Allow", 2: "FileAttrib"}.get(self.rule_type, f"Unknown({self.rule_type})")


@dataclass
class AllowedSigner:
    signer_index: int
    except_deny_rule_indices: list[int] = field(default_factory=list)


@dataclass
class DeniedSigner:
    signer_index: int
    except_allow_rule_indices: list[int] = field(default_factory=list)


@dataclass
class SignerGroup:
    allowed_signers: list[AllowedSigner] = field(default_factory=list)
    denied_signers: list[DeniedSigner] = field(default_factory=list)
    file_rules_ref_indices: list[int] = field(default_factory=list)


@dataclass
class Signer:
    cert_root_type: int   # 0=TBS hash, 1=WellKnown
    cert_root: bytes      # TBS hash or well-known value
    eku_indices: list[int] = field(default_factory=list)
    cert_issuer: str = ""
    cert_publisher: str = ""
    cert_oem_id: str = ""
    file_attrib_indices: list[int] = field(default_factory=list)
    # V3+
    sign_time_after: str = ""


@dataclass
class SigningScenario:
    value: int            # 131=Drivers, 12=User mode
    inherited: bool = False
    inherited_scenario_indices: list[int] = field(default_factory=list)
    min_hash_algo: int = 0
    product_signers: SignerGroup = field(default_factory=SignerGroup)
    test_signers: SignerGroup = field(default_factory=SignerGroup)
    test_signing_signers: SignerGroup = field(default_factory=SignerGroup)

    @property
    def scenario_name(self) -> str:
        return {131: "Drivers", 12: "User mode"}.get(self.value, f"Unknown({self.value})")


@dataclass
class SecureSetting:
    provider: str
    key: str
    value_name: str
    value_type: int       # 0=Bool, 1=DWord, 2=Binary, 3=String
    value: object = None


@dataclass
class PolicyData:
    format_version: int = 0
    policy_type_id: Optional[uuid.UUID] = None
    platform_id: Optional[uuid.UUID] = None
    option_flags: int = 0
    version_ex: str = ""
    header_length: int = 0
    ekus: list[EKURule] = field(default_factory=list)
    file_rules: list[FileRule] = field(default_factory=list)
    signers: list[Signer] = field(default_factory=list)
    update_policy_signers: list[int] = field(default_factory=list)
    ci_signers: list[int] = field(default_factory=list)
    signing_scenarios: list[SigningScenario] = field(default_factory=list)
    hvci_options: int = 0
    secure_settings: list[SecureSetting] = field(default_factory=list)
    # V6+
    policy_id: Optional[uuid.UUID] = None
    base_policy_id: Optional[uuid.UUID] = None
    supplemental_policy_signers: list[int] = field(default_factory=list)

    @property
    def policy_type_name(self) -> str:
        if self.policy_type_id is None:
            return "Unknown"
        return POLICY_TYPE_NAMES.get(str(self.policy_type_id), str(self.policy_type_id))


# ── Binary reading helpers ───────────────────────────────────────────────────

def read_uint32(data: bytes, off: int) -> tuple[int, int]:
    return struct.unpack_from("<I", data, off)[0], off + 4


def read_int32(data: bytes, off: int) -> tuple[int, int]:
    return struct.unpack_from("<i", data, off)[0], off + 4


def read_uint16(data: bytes, off: int) -> tuple[int, int]:
    return struct.unpack_from("<H", data, off)[0], off + 2


def pad4(n: int) -> int:
    """Round up to next 4-byte boundary."""
    return (n + 3) & ~3


def read_padded_bytes(data: bytes, off: int) -> tuple[bytes, int]:
    """Read UInt32 length + raw bytes, padded to 4-byte boundary."""
    length, off = read_uint32(data, off)
    raw = data[off:off + length]
    off += pad4(length)
    return raw, off


def read_utf16_string(data: bytes, off: int) -> tuple[str, int]:
    """Read UInt32 byte-length + UTF-16LE string + pad + trailing Int32."""
    byte_len, off = read_uint32(data, off)
    if byte_len == 0:
        # Still consume the trailing Int32
        _, off = read_int32(data, off)
        return "", off
    raw = data[off:off + byte_len]
    off += pad4(byte_len)
    # Trailing Int32 sentinel
    _, off = read_int32(data, off)
    text = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    return text, off


def read_guid(data: bytes, off: int) -> tuple[uuid.UUID, int]:
    """Read 16 bytes as a GUID (bytes_le format)."""
    raw = data[off:off + 16]
    return uuid.UUID(bytes_le=raw), off + 16


def read_version(data: bytes, off: int) -> tuple[str, int]:
    """Read 4 x UInt16 stored as (Rev, Build, Minor, Major), return Major.Minor.Build.Rev."""
    rev, off = read_uint16(data, off)
    build, off = read_uint16(data, off)
    minor, off = read_uint16(data, off)
    major, off = read_uint16(data, off)
    return f"{major}.{minor}.{build}.{rev}", off


def decode_oid(raw: bytes) -> str:
    """Decode OID from binary EKU value.

    Binary format: [type byte] [length byte] [OID encoded bytes]
    The OID bytes use standard ASN.1 variable-length encoding.
    """
    if len(raw) < 3:
        return ""
    # Skip 2-byte header (type + length)
    oid_bytes = raw[2:]
    # First byte encodes first two components: val = 40*X + Y
    result = [str(oid_bytes[0] // 40), str(oid_bytes[0] % 40)]
    value = 0
    for b in oid_bytes[1:]:
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            result.append(str(value))
            value = 0
    return ".".join(result)


# ── PKCS#7 / DER unwrapping ─────────────────────────────────────────────────

def _der_read_tag_length(data: bytes, off: int) -> tuple[int, int, int]:
    """Read DER tag and length, return (tag, content_length, new_offset)."""
    tag = data[off]
    off += 1
    length_byte = data[off]
    off += 1
    if length_byte < 0x80:
        return tag, length_byte, off
    num_bytes = length_byte & 0x7F
    length = int.from_bytes(data[off:off + num_bytes], "big")
    off += num_bytes
    return tag, length, off


def unwrap_pkcs7(data: bytes) -> bytes:
    """Extract the eContent from a PKCS#7 SignedData structure.

    Navigates: SEQUENCE → OID 1.2.840.113549.1.7.2 → [0] EXPLICIT →
    SEQUENCE → encapContentInfo → eContent OCTET STRING.
    """
    SIGNED_DATA_OID = bytes([0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02])

    # Check if it looks like a raw (unsigned) policy
    # Format version at offset 0, header_length at offset 0x40
    if len(data) >= 0x44:
        fmt_ver = struct.unpack_from("<I", data, 0)[0]
        if 1 <= fmt_ver <= 12:
            hdr_len = struct.unpack_from("<I", data, 0x40)[0]
            if hdr_len == 0x40:
                return data

    # Find SignedData OID
    idx = data.find(SIGNED_DATA_OID)
    if idx < 0:
        raise ValueError("Not a PKCS#7 SignedData structure and not a raw policy")

    # Move past OID to [0] EXPLICIT tag
    off = idx + len(SIGNED_DATA_OID)
    tag, length, off = _der_read_tag_length(data, off)
    if tag != 0xA0:
        raise ValueError(f"Expected [0] EXPLICIT (0xA0), got 0x{tag:02X}")

    # Inner SEQUENCE (SignedData)
    tag, length, off = _der_read_tag_length(data, off)
    if tag != 0x30:
        raise ValueError(f"Expected SEQUENCE (0x30), got 0x{tag:02X}")
    seq_start = off

    # version INTEGER
    tag, length, off = _der_read_tag_length(data, off)
    off += length  # skip version value

    # digestAlgorithms SET
    tag, length, off = _der_read_tag_length(data, off)
    off += length  # skip

    # encapContentInfo SEQUENCE
    tag, length, off = _der_read_tag_length(data, off)
    if tag != 0x30:
        raise ValueError(f"Expected encapContentInfo SEQUENCE, got 0x{tag:02X}")
    encap_end = off + length

    # contentType OID inside encapContentInfo
    tag, length, off = _der_read_tag_length(data, off)
    off += length  # skip contentType OID

    # eContent [0] EXPLICIT
    if off >= encap_end:
        raise ValueError("No eContent in encapContentInfo")
    tag, length, off = _der_read_tag_length(data, off)
    if tag != 0xA0:
        raise ValueError(f"Expected eContent [0] EXPLICIT, got 0x{tag:02X}")

    # OCTET STRING containing the actual policy
    tag, length, off = _der_read_tag_length(data, off)
    if tag != 0x04:
        raise ValueError(f"Expected OCTET STRING (0x04), got 0x{tag:02X}")

    return data[off:off + length]


# ── Header parsing ───────────────────────────────────────────────────────────

def parse_header(data: bytes) -> tuple[PolicyData, int]:
    """Parse the 0x44-byte policy header, return (PolicyData, body_offset).

    Layout (68 bytes = 0x44):
      0x00: FormatVersion    (UInt32)
      0x04: PolicyTypeID     (GUID, 16 bytes)
      0x14: PlatformID       (GUID, 16 bytes)
      0x24: OptionFlags      (UInt32)
      0x28: EKUCount         (UInt32)
      0x2C: FileRuleCount    (UInt32)
      0x30: SignerCount       (UInt32)
      0x34: ScenarioCount    (UInt32)
      0x38: VersionEx        (4 x UInt16)
      0x40: HeaderLength     (UInt32, always 0x40)
    Body starts at offset 0x44.
    """
    policy = PolicyData()
    off = 0

    policy.format_version, off = read_uint32(data, off)
    if policy.format_version > 12:
        raise ValueError(f"Unsupported format version: {policy.format_version}")

    # PolicyTypeID GUID (offset 0x04)
    policy.policy_type_id, off = read_guid(data, off)

    # PlatformID GUID (offset 0x14)
    policy.platform_id, off = read_guid(data, off)

    # Option flags (offset 0x24) — high bit (0x80000000) is a validity marker
    policy.option_flags, off = read_uint32(data, off)

    # Counts (offset 0x28-0x37)
    eku_count, off = read_uint32(data, off)
    file_rule_count, off = read_uint32(data, off)
    signer_count, off = read_uint32(data, off)
    scenario_count, off = read_uint32(data, off)

    # VersionEx (offset 0x38, 4 x UInt16)
    policy.version_ex, off = read_version(data, off)

    # HeaderLength (offset 0x40) — always 0x40
    policy.header_length, off = read_uint32(data, off)

    # Body starts at 0x44
    body_off = 0x44

    return policy, body_off, eku_count, file_rule_count, signer_count, scenario_count


# ── Body section parsers ─────────────────────────────────────────────────────

def parse_ekus(data: bytes, off: int, count: int) -> tuple[list[EKURule], int]:
    """Parse EKU rules section."""
    ekus = []
    for _ in range(count):
        raw, off = read_padded_bytes(data, off)
        oid = decode_oid(raw)
        friendly = KNOWN_EKUS.get(oid, oid)
        ekus.append(EKURule(oid=oid, friendly_name=friendly, raw_bytes=raw))
    return ekus, off


def parse_file_rules(data: bytes, off: int, count: int) -> tuple[list[FileRule], int]:
    """Parse file rules section."""
    rules = []
    for _ in range(count):
        rule_type, off = read_uint32(data, off)
        file_name, off = read_utf16_string(data, off)
        min_version, off = read_version(data, off)
        hash_value, off = read_padded_bytes(data, off)
        rules.append(FileRule(
            rule_type=rule_type,
            file_name=file_name,
            min_version=min_version,
            hash_value=hash_value,
        ))
    return rules, off


def parse_signer_group(data: bytes, off: int) -> tuple[SignerGroup, int]:
    """Parse a signer group: Allowed + Denied + FileRulesRef."""
    group = SignerGroup()

    # Allowed signers
    allowed_count, off = read_uint32(data, off)
    for _ in range(allowed_count):
        signer_idx, off = read_uint32(data, off)
        except_count, off = read_uint32(data, off)
        except_indices = []
        for _ in range(except_count):
            idx, off = read_uint32(data, off)
            except_indices.append(idx)
        group.allowed_signers.append(AllowedSigner(
            signer_index=signer_idx,
            except_deny_rule_indices=except_indices,
        ))

    # Denied signers
    denied_count, off = read_uint32(data, off)
    for _ in range(denied_count):
        signer_idx, off = read_uint32(data, off)
        except_count, off = read_uint32(data, off)
        except_indices = []
        for _ in range(except_count):
            idx, off = read_uint32(data, off)
            except_indices.append(idx)
        group.denied_signers.append(DeniedSigner(
            signer_index=signer_idx,
            except_allow_rule_indices=except_indices,
        ))

    # FileRulesRef indices
    fileref_count, off = read_uint32(data, off)
    for _ in range(fileref_count):
        idx, off = read_uint32(data, off)
        group.file_rules_ref_indices.append(idx)

    return group, off


def parse_signers(data: bytes, off: int, count: int) -> tuple[list[Signer], int]:
    """Parse signers section.

    CertRoot format differs by type:
      - TBS (type=0): UInt32 length + bytes + padding (standard padded bytes)
      - WellKnown (type=1): single UInt32 value (low byte = well-known index)
    """
    signers = []
    for _ in range(count):
        cert_root_type, off = read_uint32(data, off)

        if cert_root_type == 0:
            # TBS hash — length-prefixed padded bytes
            cert_root, off = read_padded_bytes(data, off)
        else:
            # WellKnown — single UInt32, take low byte
            val, off = read_uint32(data, off)
            cert_root = bytes([val & 0xFF])

        eku_count, off = read_uint32(data, off)
        eku_indices = []
        for _ in range(eku_count):
            idx, off = read_uint32(data, off)
            eku_indices.append(idx)

        cert_issuer, off = read_utf16_string(data, off)
        cert_publisher, off = read_utf16_string(data, off)
        cert_oem_id, off = read_utf16_string(data, off)

        file_attrib_count, off = read_uint32(data, off)
        file_attrib_indices = []
        for _ in range(file_attrib_count):
            idx, off = read_uint32(data, off)
            file_attrib_indices.append(idx)

        signers.append(Signer(
            cert_root_type=cert_root_type,
            cert_root=cert_root,
            eku_indices=eku_indices,
            cert_issuer=cert_issuer,
            cert_publisher=cert_publisher,
            cert_oem_id=cert_oem_id,
            file_attrib_indices=file_attrib_indices,
        ))
    return signers, off


def parse_index_list(data: bytes, off: int) -> tuple[list[int], int]:
    """Parse a count + list of UInt32 indices."""
    count, off = read_uint32(data, off)
    indices = []
    for _ in range(count):
        idx, off = read_uint32(data, off)
        indices.append(idx)
    return indices, off


def parse_signing_scenarios(data: bytes, off: int, count: int) -> tuple[list[SigningScenario], int]:
    """Parse signing scenarios section.

    Per-scenario: value (UInt32, low byte) → inherited count + indices →
    min hash algo (UInt32, low 16 bits) → 3 signer groups.
    """
    scenarios = []
    for _ in range(count):
        raw_value, off = read_uint32(data, off)
        scenario = SigningScenario(value=raw_value & 0xFF)

        # Inherited scenario indices (count + indices, no separate bool)
        scenario.inherited_scenario_indices, off = parse_index_list(data, off)
        scenario.inherited = len(scenario.inherited_scenario_indices) > 0

        # Minimum hash algorithm (UInt32, masked to UInt16)
        raw_algo, off = read_uint32(data, off)
        scenario.min_hash_algo = raw_algo & 0xFFFF

        # 3 signer groups: Product, Test, TestSigning
        scenario.product_signers, off = parse_signer_group(data, off)
        scenario.test_signers, off = parse_signer_group(data, off)
        scenario.test_signing_signers, off = parse_signer_group(data, off)

        scenarios.append(scenario)
    return scenarios, off


def parse_secure_settings(data: bytes, off: int) -> tuple[list[SecureSetting], int]:
    """Parse secure settings section."""
    count, off = read_uint32(data, off)
    settings = []
    for _ in range(count):
        provider, off = read_utf16_string(data, off)
        key, off = read_utf16_string(data, off)
        value_name, off = read_utf16_string(data, off)
        value_type, off = read_uint32(data, off)

        if value_type == 0:  # Bool
            val, off = read_uint32(data, off)
            value = bool(val)
        elif value_type == 1:  # DWord
            value, off = read_uint32(data, off)
        elif value_type == 2:  # Binary
            value, off = read_padded_bytes(data, off)
        elif value_type == 3:  # String
            value, off = read_utf16_string(data, off)
        else:
            value, off = read_padded_bytes(data, off)

        settings.append(SecureSetting(
            provider=provider, key=key, value_name=value_name,
            value_type=value_type, value=value,
        ))
    return settings, off


# ── Versioned extensions (V3-V8) ────────────────────────────────────────────

def parse_versioned_extensions(data: bytes, off: int, policy: PolicyData) -> int:
    """Parse version-specific extension blocks (V3 through V7).

    Structure is nested: each block reads a marker, processes content,
    then reads the NEXT marker. V8 is always the terminator (no content).
    """
    fmt = policy.format_version
    if fmt < 3 or off + 4 > len(data):
        return off

    # V3
    marker, off = read_uint32(data, off)
    if marker != 3 or fmt < 3:
        return off  # no V3+ extensions
    off = _parse_v3(data, off, policy)

    # V4
    if off + 4 > len(data):
        return off
    marker, off = read_uint32(data, off)
    if marker != 4 or fmt < 4:
        return off
    off = _parse_v4(data, off, policy)

    # V5
    if off + 4 > len(data):
        return off
    marker, off = read_uint32(data, off)
    if marker != 5 or fmt < 5:
        return off
    off = _parse_v5(data, off, policy)

    # V6
    if off + 4 > len(data):
        return off
    marker, off = read_uint32(data, off)
    if marker != 6 or fmt < 6:
        return off
    off = _parse_v6(data, off, policy)

    # V7
    if off + 4 > len(data):
        return off
    marker, off = read_uint32(data, off)
    if marker != 7 or fmt < 7:
        return off
    off = _parse_v7(data, off, policy)

    # V8 terminator (no content, just the marker)
    if off + 4 <= len(data):
        marker, off = read_uint32(data, off)
        # Expected: 8

    return off


def _parse_v3(data: bytes, off: int, policy: PolicyData) -> int:
    """V3: MaxVersion + MacroStrings(AppIDs) per FileRule; SignTimeAfter per Signer."""
    for rule in policy.file_rules:
        rule.max_version, off = read_version(data, off)
        # MacroStrings: count + N strings (joined)
        macro_count, off = read_uint32(data, off)
        if macro_count:
            parts = []
            for _ in range(macro_count):
                s, off = read_utf16_string(data, off)
                parts.append(s)
            rule.app_ids = "".join(parts)
    for signer in policy.signers:
        filetime = struct.unpack_from("<q", data, off)[0]
        off += 8
        if filetime > 0:
            signer.sign_time_after = _filetime_to_iso(filetime)
    return off


def _parse_v4(data: bytes, off: int, policy: PolicyData) -> int:
    """V4: InternalName, FileDescription, ProductName per FileRule."""
    for rule in policy.file_rules:
        rule.internal_name, off = read_utf16_string(data, off)
        rule.file_description, off = read_utf16_string(data, off)
        rule.product_name, off = read_utf16_string(data, off)
    return off


def _parse_v5(data: bytes, off: int, policy: PolicyData) -> int:
    """V5: PackageFamilyName + PackageVersion per FileRule."""
    for rule in policy.file_rules:
        rule.package_family_name, off = read_utf16_string(data, off)
        rule.package_version, off = read_version(data, off)
    return off


def _parse_v6(data: bytes, off: int, policy: PolicyData) -> int:
    """V6: PolicyID, BasePolicyID, SupplementalPolicySigners."""
    policy.policy_id, off = read_guid(data, off)
    policy.base_policy_id, off = read_guid(data, off)
    policy.supplemental_policy_signers, off = parse_index_list(data, off)
    return off


def _parse_v7(data: bytes, off: int, policy: PolicyData) -> int:
    """V7: FilePath per FileRule."""
    for rule in policy.file_rules:
        rule.file_path, off = read_utf16_string(data, off)
    return off



def _filetime_to_iso(filetime: int) -> str:
    """Convert Windows FILETIME (100ns since 1601-01-01) to ISO 8601."""
    import datetime
    EPOCH_DIFF = 116444736000000000  # 100ns intervals between 1601 and 1970
    if filetime <= EPOCH_DIFF:
        return ""
    timestamp = (filetime - EPOCH_DIFF) / 10_000_000
    try:
        dt = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OSError, ValueError):
        return f"0x{filetime:016X}"


# ── Main parser ──────────────────────────────────────────────────────────────

def parse_policy(raw_data: bytes) -> PolicyData:
    """Parse a WDAC binary policy from raw bytes (handles PKCS#7 wrapping)."""
    data = unwrap_pkcs7(raw_data)

    policy, off, eku_count, file_rule_count, signer_count, scenario_count = parse_header(data)

    # Body sections — sequential
    policy.ekus, off = parse_ekus(data, off, eku_count)
    policy.file_rules, off = parse_file_rules(data, off, file_rule_count)
    policy.signers, off = parse_signers(data, off, signer_count)
    policy.update_policy_signers, off = parse_index_list(data, off)
    policy.ci_signers, off = parse_index_list(data, off)
    policy.signing_scenarios, off = parse_signing_scenarios(data, off, scenario_count)

    # HVCI options
    if off + 4 <= len(data):
        policy.hvci_options, off = read_uint32(data, off)

    # Secure settings
    if off + 4 <= len(data):
        policy.secure_settings, off = parse_secure_settings(data, off)

    # Versioned extensions (V3+)
    off = parse_versioned_extensions(data, off, policy)

    return policy


def parse_file(path: str) -> PolicyData:
    """Parse a WDAC policy from a file path."""
    with open(path, "rb") as f:
        raw = f.read()
    return parse_policy(raw)


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Parse WDAC binary policy (.cip/.p7b) to XML",
    )
    parser.add_argument("input", help="Path to binary policy file (.cip or .p7b)")
    parser.add_argument("-o", "--output", help="Output XML file (default: stdout)")
    parser.add_argument("--info", action="store_true", help="Print policy summary instead of XML")
    args = parser.parse_args()

    policy = parse_file(args.input)

    if args.info:
        _print_info(policy)
        return

    xml_str = serialize_policy(policy)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(xml_str)
        print(f"Written to {args.output}")
        _print_info(policy)
    else:
        print(xml_str)


def _print_info(policy: PolicyData):
    """Print a summary of the parsed policy."""
    print(f"\n--- Policy Summary ---")
    print(f"Format version:  {policy.format_version}")
    print(f"Policy version:  {policy.version_ex}")
    print(f"Policy type:     {policy.policy_type_name}")
    if policy.policy_id:
        print(f"Policy ID:       {{{policy.policy_id}}}")
    if policy.base_policy_id:
        print(f"Base policy ID:  {{{policy.base_policy_id}}}")
    print(f"EKUs:            {len(policy.ekus)}")
    print(f"File rules:      {len(policy.file_rules)}")

    type_counts = {}
    for r in policy.file_rules:
        type_counts[r.type_name] = type_counts.get(r.type_name, 0) + 1
    for t, c in sorted(type_counts.items()):
        print(f"  {t}: {c}")

    print(f"Signers:         {len(policy.signers)}")
    print(f"Scenarios:       {len(policy.signing_scenarios)}")
    for s in policy.signing_scenarios:
        print(f"  {s.scenario_name} (value={s.value})")
    print(f"HVCI options:    {policy.hvci_options}")
    print(f"Secure settings: {len(policy.secure_settings)}")

    # Decoded option flags
    flags = []
    for flag_val, flag_name in sorted(OPTION_FLAGS.items()):
        if policy.option_flags & flag_val:
            flags.append(flag_name)
    if flags:
        print(f"Option flags:    {', '.join(flags)}")


if __name__ == "__main__":
    main()
