"""
WDAC XML Serializer — converts parsed PolicyData to Microsoft SiPolicy XML.
"""

import xml.etree.ElementTree as ET
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wdac_parser import PolicyData, FileRule, Signer, SigningScenario, SignerGroup

# ── Option flags → XML option element names ──────────────────────────────────

OPTION_FLAG_NAMES = {
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

HASH_ALGO_MAP = {
    0x8004: "SHA1",
    0x800C: "SHA256",
    0x800D: "SHA384",
    0x800E: "SHA512",
}


# ── ID generation ────────────────────────────────────────────────────────────

def _signer_id(idx: int) -> str:
    return f"ID_SIGNER_S_{idx + 1:04X}"


def _allow_id(idx: int) -> str:
    return f"ID_ALLOW_A_{idx + 1:04X}"


def _deny_id(idx: int) -> str:
    return f"ID_DENY_D_{idx + 1:04X}"


def _fileattrib_id(idx: int) -> str:
    return f"ID_FILEATTRIB_F_{idx + 1:04X}"


def _eku_id(idx: int) -> str:
    return f"ID_EKU_E_{idx + 1:04X}"


def _file_rule_id(rule, idx: int) -> str:
    """Map a file rule to the correct ID based on its type and GLOBAL index."""
    if rule.rule_type == 0:
        return _deny_id(idx)
    elif rule.rule_type == 1:
        return _allow_id(idx)
    else:
        return _fileattrib_id(idx)


def _guid_str(guid) -> str:
    """Format a UUID with braces, uppercase: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}."""
    if guid is None:
        return ""
    return "{" + str(guid).upper() + "}"


def _version_str(ver: str) -> str:
    """Ensure version string is present; default to 0.0.0.0."""
    return ver if ver and ver != "0.0.0.0" else "0.0.0.0"


def _hash_hex(data: bytes) -> str:
    """Convert hash bytes to uppercase hex string."""
    return data.hex().upper() if data else ""


# ── Build XML tree ───────────────────────────────────────────────────────────

def serialize_policy(policy: "PolicyData") -> str:
    """Serialize PolicyData to Microsoft SiPolicy XML string."""
    root = ET.Element("SiPolicy", {
        "xmlns": "urn:schemas-microsoft-com:sipolicy",
        "PolicyType": policy.policy_type_name,
    })

    # VersionEx
    ET.SubElement(root, "VersionEx").text = policy.version_ex

    # PolicyTypeID / PlatformID
    ET.SubElement(root, "PolicyTypeID").text = _guid_str(policy.policy_type_id)
    ET.SubElement(root, "PlatformID").text = _guid_str(policy.platform_id)

    # PolicyID / BasePolicyID (V6+)
    if policy.policy_id:
        ET.SubElement(root, "PolicyID").text = _guid_str(policy.policy_id)
    if policy.base_policy_id:
        ET.SubElement(root, "BasePolicyID").text = _guid_str(policy.base_policy_id)

    # Rules (option flags)
    rules_el = ET.SubElement(root, "Rules")
    for flag_val, flag_name in sorted(OPTION_FLAG_NAMES.items()):
        if policy.option_flags & flag_val:
            rule_el = ET.SubElement(rules_el, "Rule")
            ET.SubElement(rule_el, "Option").text = flag_name

    # EKUs
    ekus_el = ET.SubElement(root, "EKUs")
    for i, eku in enumerate(policy.ekus):
        eku_el = ET.SubElement(ekus_el, "EKU", {
            "ID": _eku_id(i),
            "FriendlyName": eku.friendly_name,
            "Value": _encode_eku_value(eku.raw_bytes),
        })

    # FileRules
    file_rules_el = ET.SubElement(root, "FileRules")
    for i, rule in enumerate(policy.file_rules):
        _build_file_rule_element(file_rules_el, rule, i)

    # Signers
    signers_el = ET.SubElement(root, "Signers")
    for i, signer in enumerate(policy.signers):
        _build_signer_element(signers_el, signer, i, policy)

    # SigningScenarios
    scenarios_el = ET.SubElement(root, "SigningScenarios")
    for scenario in policy.signing_scenarios:
        _build_scenario_element(scenarios_el, scenario, policy)

    # UpdatePolicySigners
    ups_el = ET.SubElement(root, "UpdatePolicySigners")
    for idx in policy.update_policy_signers:
        ET.SubElement(ups_el, "UpdatePolicySigner", {"SignerId": _signer_id(idx)})

    # CiSigners
    ci_el = ET.SubElement(root, "CiSigners")
    for idx in policy.ci_signers:
        ET.SubElement(ci_el, "CiSigner", {"SignerId": _signer_id(idx)})

    # SupplementalPolicySigners (V6+)
    if policy.supplemental_policy_signers:
        sps_el = ET.SubElement(root, "SupplementalPolicySigners")
        for idx in policy.supplemental_policy_signers:
            ET.SubElement(sps_el, "SupplementalPolicySigner", {"SignerId": _signer_id(idx)})

    # HvciOptions
    ET.SubElement(root, "HvciOptions").text = str(policy.hvci_options)

    # Settings (Secure Settings)
    if policy.secure_settings:
        settings_el = ET.SubElement(root, "Settings")
        for setting in policy.secure_settings:
            _build_setting_element(settings_el, setting)

    # Pretty-print
    ET.indent(root, space="  ")
    xml_decl = '<?xml version="1.0" encoding="utf-8"?>\n'
    return xml_decl + ET.tostring(root, encoding="unicode")


# ── Element builders ─────────────────────────────────────────────────────────

def _build_file_rule_element(parent: ET.Element, rule: "FileRule", idx: int):
    """Build a single FileRule XML element (Allow/Deny/FileAttrib)."""
    tag_map = {0: "Deny", 1: "Allow", 2: "FileAttrib"}
    tag = tag_map.get(rule.rule_type, "Allow")
    rule_id = _file_rule_id(rule, idx)

    attrs = {"ID": rule_id, "FriendlyName": rule.file_name or ""}

    if rule.file_name:
        attrs["FileName"] = rule.file_name
    if rule.min_version and rule.min_version != "0.0.0.0":
        attrs["MinimumFileVersion"] = rule.min_version
    if rule.max_version and rule.max_version != "0.0.0.0":
        attrs["MaximumFileVersion"] = rule.max_version
    if rule.internal_name:
        attrs["InternalName"] = rule.internal_name
    if rule.file_description:
        attrs["FileDescription"] = rule.file_description
    if rule.product_name:
        attrs["ProductName"] = rule.product_name
    if rule.package_family_name:
        attrs["PackageFamilyName"] = rule.package_family_name
    if rule.package_version and rule.package_version != "0.0.0.0":
        attrs["PackageVersion"] = rule.package_version
    if rule.file_path:
        attrs["FilePath"] = rule.file_path
    if rule.app_ids:
        attrs["AppIDs"] = rule.app_ids

    el = ET.SubElement(parent, tag, attrs)

    # Hash element
    if rule.hash_value:
        hash_el = ET.SubElement(el, "Hash")
        hash_el.text = _hash_hex(rule.hash_value)

    return el


def _build_signer_element(parent: ET.Element, signer: "Signer", idx: int, policy: "PolicyData"):
    """Build a single Signer XML element."""
    signer_el = ET.SubElement(parent, "Signer", {
        "ID": _signer_id(idx),
        "Name": signer.cert_issuer or f"Signer {idx}",
    })

    # CertRoot
    if signer.cert_root_type == 1:
        # WellKnown
        well_known_val = signer.cert_root[0] if signer.cert_root else 0
        well_known_map = {
            1: "Microsoft Authenticode(tm) Root Authority",
            2: "Microsoft Root Authority",
            3: "Microsoft Root Certificate Authority",
            4: "Microsoft Root Certificate Authority 2010",
            5: "Microsoft Root Certificate Authority 2011",
            6: "Microsoft Testing Root Certificate Authority 2010",
            7: "Microsoft Development Root Certificate Authority 2014",
            8: "Microsoft Standard Root Certificate Authority 2011",
        }
        ET.SubElement(signer_el, "CertRoot", {
            "Type": "Wellknown",
            "Value": f"{well_known_val:02X}",
        })
    else:
        # TBS hash
        ET.SubElement(signer_el, "CertRoot", {
            "Type": "TBS",
            "Value": _hash_hex(signer.cert_root),
        })

    # CertEKU references
    for eku_idx in signer.eku_indices:
        if eku_idx < len(policy.ekus):
            ET.SubElement(signer_el, "CertEKU", {"ID": _eku_id(eku_idx)})

    # CertIssuer
    if signer.cert_issuer:
        ET.SubElement(signer_el, "CertIssuer", {"Value": signer.cert_issuer})

    # CertPublisher
    if signer.cert_publisher:
        ET.SubElement(signer_el, "CertPublisher", {"Value": signer.cert_publisher})

    # CertOemID
    if signer.cert_oem_id:
        ET.SubElement(signer_el, "CertOemID", {"Value": signer.cert_oem_id})

    # FileAttribRef
    for fa_idx in signer.file_attrib_indices:
        ET.SubElement(signer_el, "FileAttribRef", {"RuleID": _fileattrib_id(fa_idx)})

    # SignTimeAfter (V3+)
    if signer.sign_time_after:
        ET.SubElement(signer_el, "SignTimeAfter").text = signer.sign_time_after

    return signer_el


_driver_scenario_count = 0
_windows_scenario_count = 0

def _scenario_id(scenario) -> str:
    """Generate scenario ID matching PowerShell format."""
    global _driver_scenario_count, _windows_scenario_count
    if scenario.value == 131:
        _driver_scenario_count += 1
        return f"ID_SIGNINGSCENARIO_DRIVERS_{_driver_scenario_count:X}"
    elif scenario.value == 12:
        _windows_scenario_count += 1
        if _windows_scenario_count == 1:
            return "ID_SIGNINGSCENARIO_WINDOWS"
        return f"ID_SIGNINGSCENARIO_WINDOWS_{_windows_scenario_count:X}"
    return f"ID_SIGNINGSCENARIO_S_{scenario.value:04X}"


def _build_scenario_element(parent: ET.Element, scenario: "SigningScenario", policy: "PolicyData"):
    """Build a SigningScenario XML element."""
    scenario_el = ET.SubElement(parent, "SigningScenario", {
        "Value": str(scenario.value),
        "ID": _scenario_id(scenario),
    })

    if scenario.inherited:
        ET.SubElement(scenario_el, "Inherited").text = "true"

    # MinimumHashAlgorithm
    algo_name = HASH_ALGO_MAP.get(scenario.min_hash_algo, "")
    if algo_name:
        ET.SubElement(scenario_el, "MinimumHashAlgorithm").text = algo_name

    # ProductSigners
    _build_signer_group_element(scenario_el, "ProductSigners", scenario.product_signers, policy)
    # TestSigners
    _build_signer_group_element(scenario_el, "TestSigners", scenario.test_signers, policy)
    # TestSigningSigners
    _build_signer_group_element(scenario_el, "TestSigningSigners", scenario.test_signing_signers, policy)


def _build_signer_group_element(parent: ET.Element, tag: str, group: "SignerGroup", policy: "PolicyData"):
    """Build a signer group (ProductSigners/TestSigners/TestSigningSigners)."""
    group_el = ET.SubElement(parent, tag)

    # AllowedSigners
    if group.allowed_signers:
        allowed_el = ET.SubElement(group_el, "AllowedSigners")
        for allowed in group.allowed_signers:
            as_el = ET.SubElement(allowed_el, "AllowedSigner", {
                "SignerId": _signer_id(allowed.signer_index),
            })
            for deny_idx in allowed.except_deny_rule_indices:
                ET.SubElement(as_el, "ExceptDenyRule", {"DenyRuleID": _deny_id(deny_idx)})

    # DeniedSigners
    if group.denied_signers:
        denied_el = ET.SubElement(group_el, "DeniedSigners")
        for denied in group.denied_signers:
            ds_el = ET.SubElement(denied_el, "DeniedSigner", {
                "SignerId": _signer_id(denied.signer_index),
            })
            for allow_idx in denied.except_allow_rule_indices:
                ET.SubElement(ds_el, "ExceptAllowRule", {"AllowRuleID": _allow_id(allow_idx)})

    # FileRulesRef
    if group.file_rules_ref_indices:
        frr_el = ET.SubElement(group_el, "FileRulesRef")
        for fr_idx in group.file_rules_ref_indices:
            if fr_idx < len(policy.file_rules):
                rule = policy.file_rules[fr_idx]
                ET.SubElement(frr_el, "FileRuleRef", {
                    "RuleID": _file_rule_id(rule, fr_idx),
                })


def _build_setting_element(parent: ET.Element, setting):
    """Build a Setting element for secure settings."""
    setting_el = ET.SubElement(parent, "Setting", {
        "Provider": setting.provider,
        "Key": setting.key,
        "ValueName": setting.value_name,
    })

    type_map = {0: "Boolean", 1: "DWord", 2: "Binary", 3: "String"}
    type_name = type_map.get(setting.value_type, "Binary")

    value_el = ET.SubElement(setting_el, "Value")
    if setting.value_type == 0:
        ET.SubElement(value_el, type_name).text = "true" if setting.value else "false"
    elif setting.value_type == 1:
        ET.SubElement(value_el, type_name).text = str(setting.value)
    elif setting.value_type == 2:
        ET.SubElement(value_el, type_name).text = _hash_hex(setting.value) if isinstance(setting.value, bytes) else str(setting.value)
    elif setting.value_type == 3:
        ET.SubElement(value_el, type_name).text = str(setting.value)


def _encode_eku_value(raw_bytes: bytes) -> str:
    """Encode EKU raw bytes for XML Value attribute — output raw hex as-is."""
    return raw_bytes.hex().upper()
