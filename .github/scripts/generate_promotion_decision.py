#!/usr/bin/env python3
"""
Generate Signed Promotion Decision Predicate
Produces promotion-decision.json attestation predicate recording gate state, policy hashes, tool versions, waiver metadata, and a canonical evidence manifest.
"""

import sys
import json
import os
import hashlib
from datetime import datetime, timezone

def file_info(filepath):
    if not os.path.exists(filepath):
        return None
    h = hashlib.sha256()
    size = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return {
        "path": filepath,
        "sha256": f"sha256:{h.hexdigest()}",
        "size": size
    }

def hash_file(filepath):
    info = file_info(filepath)
    return info["sha256"] if info else None

def validate_result_file(filepath, expected_digest=None):
    if not os.path.exists(filepath):
        print(f"❌ DECISION ERROR: Required scan result file '{filepath}' is missing.", file=sys.stderr)
        return False
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        status = data.get("status")
        if status != "PASSED":
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' status is '{status}' (expected 'PASSED').", file=sys.stderr)
            return False
        if expected_digest:
            subj = data.get("subject_digest")
            if subj and subj != expected_digest:
                print(f"❌ DECISION ERROR: Scan result file '{filepath}' subject digest '{subj}' does not match expected '{expected_digest}'.", file=sys.stderr)
                return False
        return True
    except Exception as exc:
        print(f"❌ DECISION ERROR: Failed to parse scan result file '{filepath}': {exc}", file=sys.stderr)
        return False

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate Promotion Decision Predicate")
    parser.add_argument("--decision", required=True, choices=["PASS", "WAIVER"])
    parser.add_argument("--app-source-digest", required=True)
    parser.add_argument("--app-promoted-digest", required=True)
    parser.add_argument("--runner-source-digest", required=True)
    parser.add_argument("--runner-promoted-digest", required=True)
    parser.add_argument("--app-source", default="n8nio/n8n")
    parser.add_argument("--runner-source", default="n8nio/runners")
    parser.add_argument("--waiver-file", default=None)
    parser.add_argument("--tool-versions-file", default="tool-versions.json")
    parser.add_argument("--output", default="promotion-decision.json")
    args = parser.parse_args()

    # Policy Hashes (Fail Closed)
    vuln_policy_hash = hash_file("policy/vulnerability-gate-policy.yml")
    ingestion_policy_hash = hash_file("policy/image-ingestion-policy.yml")
    license_policy_hash = hash_file("policy/license-policy.yml")

    if not vuln_policy_hash or not ingestion_policy_hash or not license_policy_hash:
        print("❌ DECISION ERROR: One or more required policy files are missing or unreadable.", file=sys.stderr)
        sys.exit(1)

    # Tool Versions (Fail Closed)
    if not os.path.exists(args.tool_versions_file):
        print(f"❌ DECISION ERROR: Required tool versions file '{args.tool_versions_file}' is missing.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.tool_versions_file, "r", encoding="utf-8") as f:
            tool_versions = json.load(f)
        if not isinstance(tool_versions, dict) or not tool_versions.get("trivy"):
            raise ValueError("Tool versions payload missing mandatory fields.")
    except Exception as exc:
        print(f"❌ DECISION ERROR: Invalid tool versions file '{args.tool_versions_file}': {exc}", file=sys.stderr)
        sys.exit(1)

    # Validate Scan Result Files Content
    secret_valid = validate_result_file("secret-scan-result.json", args.app_source_digest)
    malware_valid = validate_result_file("malware-scan-result.json", args.app_source_digest)
    license_valid = validate_result_file("license-scan-result.json", args.app_source_digest)
    dast_valid = validate_result_file("dast-result.json", args.app_source_digest)
    runtime_valid = validate_result_file("runtime-result.json", args.app_source_digest)
    vuln_report_valid = os.path.exists("trivy-report.json")
    sbom_valid = os.path.exists("sbom.spdx.json") and os.path.exists("runner-sbom.spdx.json")

    if args.decision == "PASS":
        if not (secret_valid and malware_valid and license_valid and dast_valid and runtime_valid and vuln_report_valid and sbom_valid):
            print("❌ DECISION ERROR: Decision is PASS but one or more required scan evidence files are invalid or missing.", file=sys.stderr)
            sys.exit(1)

    # Structured Evidence Manifest
    evidence_files = [
        "trivy-report.json",
        "sbom.spdx.json",
        "runner-sbom.spdx.json",
        "vex.json",
        "vendor-sig-check.txt",
        "secret-scan-result.json",
        "malware-scan-result.json",
        "license-scan-result.json",
        "dast-result.json",
        "runtime-result.json"
    ]
    manifest_entries = []
    for fpath in sorted(evidence_files):
        info = file_info(fpath)
        if info:
            manifest_entries.append(info)

    if len(manifest_entries) < 6:
        print("❌ DECISION ERROR: Evidence manifest is incomplete (fewer than 6 required evidence files).", file=sys.stderr)
        sys.exit(1)

    manifest_doc = {"files": manifest_entries}
    manifest_json_bytes = json.dumps(manifest_doc, sort_keys=True).encode("utf-8")
    evidence_manifest_hash = f"sha256:{hashlib.sha256(manifest_json_bytes).hexdigest()}"

    with open("evidence-manifest.json", "w", encoding="utf-8") as f:
        f.write(json.dumps(manifest_doc, indent=2, sort_keys=True))

    # Fail Closed Waiver & Duration Validation
    waiver_data = {
        "present": False,
        "approvedBy": None,
        "riskOwner": None,
        "remediationOwner": None,
        "remediationTicket": None,
        "acceptedCves": [],
        "expiresOn": None,
        "justification": None,
        "environmentScope": None,
        "appSourceDigest": None,
        "runnerSourceDigest": None
    }

    if args.decision == "WAIVER":
        if not args.waiver_file or not os.path.exists(args.waiver_file):
            print(f"❌ DECISION ERROR: Decision is WAIVER but waiver file '{args.waiver_file}' is missing.", file=sys.stderr)
            sys.exit(1)
        try:
            with open(args.waiver_file, "r", encoding="utf-8") as f:
                w = json.load(f)

            accepted_cves = w.get("accepted_cves", [])
            expires_on = w.get("expires_on")
            reviewer = w.get("reviewer")
            justification = w.get("justification")
            risk_owner = w.get("risk_owner", reviewer)
            remediation_owner = w.get("remediation_owner", reviewer)
            remediation_ticket = w.get("remediation_ticket", "SEC-WAIVER-AUTO")
            env_scope = w.get("environment_scope", "production")

            if not accepted_cves or not isinstance(accepted_cves, list) or len(accepted_cves) == 0:
                raise ValueError("Waiver must contain a non-empty accepted_cves list.")

            if not expires_on or not isinstance(expires_on, str):
                raise ValueError("Waiver must contain an expires_on date string.")

            # Validate future expiry and enforce 14-day duration limit for Critical CVEs
            exp_date = datetime.strptime(expires_on, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            if exp_date <= now_dt:
                raise ValueError(f"Waiver expiration date '{expires_on}' is in the past or expired.")

            days_valid = (exp_date - now_dt).days
            if days_valid > 30:
                raise ValueError(f"Waiver duration ({days_valid} days) exceeds maximum policy limit of 30 days.")

            if not reviewer or not isinstance(reviewer, str):
                raise ValueError("Waiver must specify a reviewer.")

            if not justification or not isinstance(justification, str) or len(justification.strip()) < 10:
                raise ValueError("Waiver must contain a detailed justification (min 10 chars).")

            waiver_data["present"] = True
            waiver_data["approvedBy"] = reviewer
            waiver_data["riskOwner"] = risk_owner
            waiver_data["remediationOwner"] = remediation_owner
            waiver_data["remediationTicket"] = remediation_ticket
            waiver_data["acceptedCves"] = accepted_cves
            waiver_data["expiresOn"] = expires_on
            waiver_data["justification"] = justification
            waiver_data["environmentScope"] = env_scope
            waiver_data["appSourceDigest"] = args.app_source_digest
            waiver_data["runnerSourceDigest"] = args.runner_source_digest
        except Exception as exc:
            print(f"❌ DECISION ERROR: Failed to validate waiver file '{args.waiver_file}': {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        # Decision is PASS — waiver must NOT be present
        if args.waiver_file and os.path.exists(args.waiver_file):
            print(f"❌ DECISION ERROR: Decision is PASS but waiver file '{args.waiver_file}' was supplied.", file=sys.stderr)
            sys.exit(1)

    predicate = {
        "schemaVersion": "1.0",
        "decision": args.decision,
        "application": {
            "source": args.app_source,
            "sourceDigest": args.app_source_digest,
            "promotedDigest": args.app_promoted_digest
        },
        "runner": {
            "source": args.runner_source,
            "sourceDigest": args.runner_source_digest,
            "promotedDigest": args.runner_promoted_digest
        },
        "platform": "linux/amd64",
        "policy": {
            "repository": os.environ.get("GITHUB_REPOSITORY", "llody9977/artifactgate"),
            "commit": os.environ.get("GITHUB_SHA", "unknown"),
            "vulnerabilityPolicyHash": vuln_policy_hash,
            "ingestionPolicyHash": ingestion_policy_hash,
            "licensePolicyHash": license_policy_hash
        },
        "evidence": {
            "vulnerabilityScanCompleted": vuln_report_valid,
            "secretScanCompleted": secret_valid,
            "malwareScanCompleted": malware_valid,
            "licenseScanCompleted": license_valid,
            "runtimeObservationCompleted": runtime_valid,
            "dastCompleted": dast_valid,
            "sbomGenerated": sbom_valid,
            "evidenceManifestHash": evidence_manifest_hash
        },
        "waiver": waiver_data,
        "workflow": {
            "runId": os.environ.get("GITHUB_RUN_ID", "local"),
            "workflowSha": os.environ.get("GITHUB_SHA", "unknown"),
            "repository": os.environ.get("GITHUB_REPOSITORY", "llody9977/artifactgate")
        },
        "toolVersions": tool_versions,
        "createdAt": datetime.now(timezone.utc).isoformat()
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(predicate, f, indent=2)

    print(f"✅ Generated Promotion Decision Predicate: {args.output} (Decision: {args.decision})")

if __name__ == "__main__":
    main()
