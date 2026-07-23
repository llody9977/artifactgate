#!/usr/bin/env python3
"""
OpenVEX Semantic Attestation Validator
Validates OpenVEX documents for schema compliance, product digest binding, valid statement status, approved justifications for not_affected, and conflict-free statements.
"""

import sys
import json
import os

VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
VALID_JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_not_present",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist"
}

def validate_vex(vex_path, expected_digest=None):
    if not os.path.exists(vex_path):
        print(f"❌ VEX ERROR: OpenVEX file '{vex_path}' does not exist.", file=sys.stderr)
        return False

    try:
        with open(vex_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"❌ VEX ERROR: Failed to parse OpenVEX JSON in '{vex_path}': {exc}", file=sys.stderr)
        return False

    if not isinstance(data, dict):
        print(f"❌ VEX ERROR: OpenVEX root must be a JSON object in '{vex_path}'.", file=sys.stderr)
        return False

    context = data.get("@context")
    if not context or "openvex" not in str(context).lower():
        print(f"❌ VEX ERROR: Missing or invalid @context in '{vex_path}': {context}", file=sys.stderr)
        return False

    statements = data.get("statements")
    if not isinstance(statements, list) or len(statements) == 0:
        print(f"❌ VEX ERROR: Missing or empty statements list in '{vex_path}'.", file=sys.stderr)
        return False

    clean_target_digest = None
    if expected_digest:
        clean_target_digest = expected_digest.split("@")[-1].replace("sha256:", "").strip().lower()

    seen_vuln_statuses = {}

    for idx, stmt in enumerate(statements):
        status = stmt.get("status")
        if status not in VALID_STATUSES:
            print(f"❌ VEX ERROR: Statement [{idx}] has invalid status '{status}' in '{vex_path}'. Expected one of {VALID_STATUSES}.", file=sys.stderr)
            return False

        vuln = stmt.get("vulnerability", {})
        vuln_id = vuln.get("name") if isinstance(vuln, dict) else vuln
        if not vuln_id:
            print(f"❌ VEX ERROR: Statement [{idx}] is missing a vulnerability identifier in '{vex_path}'.", file=sys.stderr)
            return False

        # Justification check for not_affected
        if status == "not_affected":
            justification = stmt.get("justification")
            if not justification or justification not in VALID_JUSTIFICATIONS:
                print(f"❌ VEX ERROR: Statement [{idx}] for '{vuln_id}' status 'not_affected' missing valid justification. Got '{justification}'. Expected one of {VALID_JUSTIFICATIONS}.", file=sys.stderr)
                return False

        # Conflict checking
        if vuln_id in seen_vuln_statuses:
            prev_status = seen_vuln_statuses[vuln_id]
            if prev_status != status:
                print(f"❌ VEX ERROR: Statement [{idx}] for '{vuln_id}' status '{status}' conflicts with previous statement status '{prev_status}' in '{vex_path}'.", file=sys.stderr)
                return False
        else:
            seen_vuln_statuses[vuln_id] = status

        products = stmt.get("products", [])
        if not isinstance(products, list) or len(products) == 0:
            print(f"❌ VEX ERROR: Statement [{idx}] missing product references in '{vex_path}'.", file=sys.stderr)
            return False

        if clean_target_digest:
            stmt_str = json.dumps(stmt).lower()
            if clean_target_digest not in stmt_str:
                print(f"❌ VEX ERROR: Statement [{idx}] product reference does not match expected digest '{clean_target_digest}' in '{vex_path}'.", file=sys.stderr)
                return False

    print(f"✅ OpenVEX Semantic Validation PASSED for '{vex_path}': {len(statements)} statements verified.")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 validate_vex.py <path-to-vex.json> [expected_digest]")
        sys.exit(1)

    path = sys.argv[1]
    expected_dig = sys.argv[2] if len(sys.argv) > 2 else None

    if not validate_vex(path, expected_dig):
        sys.exit(1)
