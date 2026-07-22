#!/usr/bin/env python3
"""
SBOM Quality Validation Script
Validates SPDX JSON SBOM documents for schema validity, non-emptiness, and sanity thresholds.
"""

import sys
import json
import os

def validate_sbom(sbom_path, min_package_count=10):
    if not os.path.exists(sbom_path):
        print(f"❌ SBOM ERROR: File '{sbom_path}' does not exist.", file=sys.stderr)
        return False

    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"❌ SBOM ERROR: Failed to parse JSON in '{sbom_path}': {exc}", file=sys.stderr)
        return False

    # Check SPDX schema headers
    spdx_version = data.get("spdxVersion")
    spdx_id = data.get("SPDXID")
    doc_namespace = data.get("documentNamespace")

    if not spdx_version or not spdx_version.startswith("SPDX-"):
        print(f"❌ SBOM ERROR: Invalid or missing spdxVersion in '{sbom_path}': {spdx_version}", file=sys.stderr)
        return False

    if spdx_id != "SPDXRef-DOCUMENT":
        print(f"❌ SBOM ERROR: Invalid SPDXID in '{sbom_path}': {spdx_id}", file=sys.stderr)
        return False

    if not doc_namespace:
        print(f"❌ SBOM ERROR: Missing documentNamespace in '{sbom_path}'.", file=sys.stderr)
        return False

    # Check package array and sanity threshold
    packages = data.get("packages")
    if not isinstance(packages, list) or len(packages) == 0:
        print(f"❌ SBOM ERROR: Packages list in '{sbom_path}' is empty or invalid.", file=sys.stderr)
        return False

    if len(packages) < min_package_count:
        print(f"❌ SBOM ERROR: Package count in '{sbom_path}' ({len(packages)}) is below sanity threshold ({min_package_count}).", file=sys.stderr)
        return False

    # Check for scanner error markers or missing names
    for pkg in packages:
        name = pkg.get("name")
        if not name or "ERROR" in name.upper() or "CORRUPT" in name.upper():
            print(f"❌ SBOM ERROR: Malformed package entry found in '{sbom_path}': {pkg}", file=sys.stderr)
            return False

    print(f"✅ SBOM Validation Passed for '{sbom_path}': {len(packages)} packages verified under SPDX schema {spdx_version}.")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 validate_sbom.py <path-to-sbom.spdx.json> [min_packages]")
        sys.exit(1)

    path = sys.argv[1]
    min_count = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    if not validate_sbom(path, min_count):
        sys.exit(1)
