# WDAC Binary Policy Parser (Python)

First Python implementation of a Windows Defender Application Control binary policy parser. Converts `.cip` and `.p7b` binary policies to Microsoft SiPolicy XML format.

Based on [mattifestation/WDACTools](https://github.com/mattifestation/WDACTools) (PowerShell).

## Requirements

- Python 3.9+
- No external dependencies (stdlib only)

## Usage

```bash
# Output XML to stdout
python wdac_parser.py SiPolicy.p7b

# Write XML to file
python wdac_parser.py SiPolicy.p7b -o policy.xml

# Print policy summary only
python wdac_parser.py SiPolicy.p7b --info
```

## Supported Formats

| Format                        | Support |
| ----------------------------- | ------- |
| Raw unsigned policies (.cip)  | Yes     |
| PKCS#7 signed policies (.p7b) | Yes     |
| Binary format versions 1-8    | Yes     |
| Versioned extensions (V3-V7)  | Yes     |

## What Gets Parsed

- Header: format version, PolicyTypeID, PlatformID, option flags, VersionEx
- EKU rules with OID decoding and friendly names
- File rules: Deny, Allow, FileAttrib (with hashes, versions, file metadata)
- Signers: TBS hash and WellKnown root types, publisher/issuer, EKU/FileAttrib refs
- Signing scenarios: Drivers (131) and User mode (12) with signer groups
- Update policy signers and CI signers
- HVCI options
- Secure settings (Bool, DWord, Binary, String types)
- V3: MaxVersion, AppIDs (macro strings), SignTimeAfter
- V4: InternalName, FileDescription, ProductName
- V5: PackageFamilyName, PackageVersion
- V6: PolicyID, BasePolicyID, SupplementalPolicySigners
- V7: FilePath rules

## Example Output

```
--- Policy Summary ---
Format version:  8
Policy version:  10.3.0.0
Policy type:     Enterprise
EKUs:            6
File rules:      1374
  Deny: 1308
  FileAttrib: 66
Signers:         127
Scenarios:       2
  Drivers (value=131)
  User mode (value=12)
HVCI options:    0
Secure settings: 2
Option flags:    Enabled:UMCI, Enabled:Audit Mode, ...
```

## Files

| File             | Description                                |
| ---------------- | ------------------------------------------ |
| `wdac_parser.py` | Binary parser + CLI entry point            |
| `wdac_xml.py`    | XML serializer (Microsoft SiPolicy schema) |
