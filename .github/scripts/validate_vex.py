#!/usr/bin/env python3
"""
OpenVEX Semantic Attestation Validator
Validates OpenVEX documents for schema compliance, product digest binding, valid statement status, approved justifications for not_affected, and conflict-free statements.
"""

import sys
import json
import os
from datetime import datetime, timezone


VALID_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}
VALID_JUSTIFICATIONS = {
    "code_not_present",
    "code_not_reachable",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_not_present",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist"
}

def validate_vex(vex_path, expected_digest=None, trivy_report_path=None, waiver_path=None):
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

    if not data.get("timestamp") or not data.get("author"):
        print(f"❌ VEX ERROR: Missing timestamp or author in '{vex_path}'.", file=sys.stderr)
        return False

    statements = data.get("statements")
    if not isinstance(statements, list) or len(statements) == 0:
        print(f"❌ VEX ERROR: Missing or empty statements list in '{vex_path}'.", file=sys.stderr)
        return False

    # Optional Waiver Parsing
    accepted_cves = set()
    waiver_active = False
    if waiver_path and os.path.exists(waiver_path):
        try:
            with open(waiver_path, "r", encoding="utf-8") as wf:
                w_data = json.load(wf)
            expires_on = w_data.get("expires_on")
            if expires_on:
                exp_date = datetime.strptime(expires_on, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if exp_date > datetime.now(timezone.utc):
                    waiver_active = True
                    accepted_cves = set(w_data.get("accepted_cves", []))
        except Exception as exc:
            print(f"⚠️ VEX WARNING: Could not parse waiver file '{waiver_path}': {exc}", file=sys.stderr)

    clean_target_digest = None
    if expected_digest:
        clean_target_digest = expected_digest.split("@")[-1].replace("sha256:", "").strip().lower()

    seen_vuln_statuses = {}
    vex_vulns_by_status = {}

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

        vex_vulns_by_status[vuln_id] = status

        # Justification check for not_affected
        if status == "not_affected":
            justification = stmt.get("justification")
            if not justification or justification not in VALID_JUSTIFICATIONS:
                print(f"❌ VEX ERROR: Statement [{idx}] for '{vuln_id}' status 'not_affected' missing valid justification. Got '{justification}'. Expected one of {VALID_JUSTIFICATIONS}.", file=sys.stderr)
                return False

        # Waiver match check for affected or under_investigation
        if status in {"affected", "under_investigation"}:
            if waiver_path:
                if not os.path.exists(waiver_path) or not waiver_active or vuln_id not in accepted_cves:
                    print(f"❌ VEX ERROR: Statement [{idx}] for '{vuln_id}' status '{status}' is not covered by an active waiver.", file=sys.stderr)
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
            digest_found = False
            for p in products:
                p_id = p.get("@id", "") if isinstance(p, dict) else str(p)
                if clean_target_digest in p_id.lower():
                    digest_found = True
                    break
            if not digest_found:
                print(f"❌ VEX ERROR: Statement [{idx}] product reference does not structurally contain expected digest '{clean_target_digest}' in '{vex_path}'.", file=sys.stderr)
                return False

    # Gated CVE correspondence & waiver coverage check if trivy report provided
    if trivy_report_path and os.path.exists(trivy_report_path):
        try:
            with open(trivy_report_path, "r", encoding="utf-8") as trf:
                trivy_rep = json.load(trf)
            gated_cves = set()
            for res in trivy_rep.get("Results", []):
                for v in res.get("Vulnerabilities", []) or []:
                    if v.get("Severity") in {"CRITICAL", "HIGH"} or v.get("GateDecision") == "MANUAL_REVIEW":
                        if v.get("VulnerabilityID"):
                            gated_cves.add(v.get("VulnerabilityID"))
            missing_cves = gated_cves - set(vex_vulns_by_status.keys())
            if missing_cves:
                print(f"❌ VEX ERROR: Gated vulnerabilities {missing_cves} lack corresponding VEX statements in '{vex_path}'.", file=sys.stderr)
                return False

            # Check full waiver-to-CVE coverage across gated set
            for g_cve in gated_cves:
                st = vex_vulns_by_status.get(g_cve)
                if st in {"affected", "under_investigation"}:
                    if not waiver_active or g_cve not in accepted_cves:
                        print(f"❌ VEX ERROR: Gated vulnerability '{g_cve}' has status '{st}' in OpenVEX but lacks an active waiver.", file=sys.stderr)
                        return False
        except Exception as exc:
            print(f"❌ VEX ERROR: Failed to check trivy report correspondence '{trivy_report_path}': {exc}", file=sys.stderr)
            return False

    print(f"✅ OpenVEX Semantic Validation PASSED for '{vex_path}': {len(statements)} statements verified.")
    return True

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Validate OpenVEX Attestation")
    parser.add_argument("vex_path", help="Path to OpenVEX JSON file")
    parser.add_argument("expected_digest", nargs="?", default=None)
    parser.add_argument("trivy_report_path", nargs="?", default=None)
    parser.add_argument("waiver_path", nargs="?", default=None)
    args = parser.parse_args()

    if not validate_vex(args.vex_path, args.expected_digest, args.trivy_report_path, args.waiver_path):
        sys.exit(1)


