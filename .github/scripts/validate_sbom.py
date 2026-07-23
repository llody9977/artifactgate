#!/usr/bin/env python3
"""
Enhanced SBOM Quality Validation Script
Validates SPDX JSON SBOM documents for schema headers, creation metadata, package counts, SPDX identifiers, relationships, target digest binding, and error markers.
"""

import sys
import json
import os

def validate_sbom(sbom_path, target_digest=None, min_package_count=10):
    if not os.path.exists(sbom_path):
        print(f"❌ SBOM ERROR: File '{sbom_path}' does not exist.", file=sys.stderr)
        return False

    try:
        with open(sbom_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"❌ SBOM ERROR: Failed to parse JSON in '{sbom_path}': {exc}", file=sys.stderr)
        return False

    # 1. Check SPDX schema headers
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

    # 2. Check Creation Info & Creators
    creation_info = data.get("creationInfo", {})
    creators = creation_info.get("creators", [])
    if not creators or not isinstance(creators, list) or len(creators) == 0:
        print(f"❌ SBOM ERROR: Missing creationInfo creators metadata in '{sbom_path}'.", file=sys.stderr)
        return False

    # 3. Structured Target Digest Binding (Strict SPDX Fields)
    if target_digest:
        clean_digest = target_digest.split("@")[-1].replace("sha256:", "").strip().lower()
        digest_bound = False

        # Check document namespace
        if clean_digest in doc_namespace.lower():
            digest_bound = True

        # Check packages checksums or externalRefs structurally
        packages = data.get("packages", [])
        for pkg in packages:
            checksums = pkg.get("checksums", [])
            for c in checksums:
                c_val = str(c.get("checksumValue", "")).lower()
                if clean_digest in c_val:
                    digest_bound = True
                    break
            ext_refs = pkg.get("externalRefs", [])
            for ref in ext_refs:
                ref_loc = str(ref.get("referenceLocator", "")).lower()
                if clean_digest in ref_loc:
                    digest_bound = True
                    break
            if digest_bound:
                break

        if not digest_bound:
            print(f"❌ SBOM ERROR: Subject image digest '{clean_digest}' is not bound to document namespace or package checksum/externalRef metadata in '{sbom_path}'.", file=sys.stderr)
            return False


    # 4. Check Package Array & Thresholds
    packages = data.get("packages")
    if not isinstance(packages, list) or len(packages) == 0:
        print(f"❌ SBOM ERROR: Packages list in '{sbom_path}' is empty or invalid.", file=sys.stderr)
        return False

    if len(packages) < min_package_count:
        print(f"❌ SBOM ERROR: Package count in '{sbom_path}' ({len(packages)}) is below sanity threshold ({min_package_count}).", file=sys.stderr)
        return False

    # 5. Check Package Identifiers & Duplicate SPDXIDs
    seen_spdx_ids = set()
    for pkg in packages:
        name = pkg.get("name")
        pkg_spdx_id = pkg.get("SPDXID")

        if not name or "ERROR" in name.upper() or "CORRUPT" in name.upper():
            print(f"❌ SBOM ERROR: Malformed or error-marked package entry found in '{sbom_path}': {pkg}", file=sys.stderr)
            return False

        if not pkg_spdx_id:
            print(f"❌ SBOM ERROR: Package '{name}' is missing an SPDXID in '{sbom_path}'.", file=sys.stderr)
            return False

        if pkg_spdx_id in seen_spdx_ids:
            print(f"❌ SBOM ERROR: Duplicate SPDXID '{pkg_spdx_id}' found in '{sbom_path}'.", file=sys.stderr)
            return False
        seen_spdx_ids.add(pkg_spdx_id)

    # 6. Check Relationship References if present
    seen_spdx_ids.add("SPDXRef-DOCUMENT")
    relationships = data.get("relationships", [])
    for rel in relationships:
        elem = rel.get("spdxElementId")
        related = rel.get("relatedSpdxElement")
        if elem and elem not in seen_spdx_ids:
            print(f"❌ SBOM ERROR: Relationship element '{elem}' is not defined in '{sbom_path}'.", file=sys.stderr)
            return False
        if related and related not in seen_spdx_ids and not related.startswith("SPDXRef-DOCUMENT"):
            print(f"❌ SBOM ERROR: Related relationship element '{related}' is not defined in '{sbom_path}'.", file=sys.stderr)
            return False

    print(f"✅ Enhanced SBOM Validation Passed for '{sbom_path}': {len(packages)} packages verified under SPDX schema {spdx_version}.")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 validate_sbom.py <path-to-sbom.spdx.json> [min_packages] [target_digest]")
        sys.exit(1)

    path = sys.argv[1]
    min_count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    target_dig = sys.argv[3] if len(sys.argv) > 3 else None

    if not validate_sbom(path, target_dig, min_count):
        sys.exit(1)
