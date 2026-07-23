#!/usr/bin/env python3
"""
Generate Signed Promotion Decision Predicate
Produces promotion-decision.json attestation predicate recording decisionId, gate state, policy hashes, tool versions, waiver metadata, and a canonical evidence manifest.
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

def validate_result_file(filepath, expected_digest, expected_role, allowed_statuses=None, expected_run_id=None):
    if allowed_statuses is None:
        allowed_statuses = {"PASSED"}
    if not os.path.exists(filepath):
        print(f"❌ DECISION ERROR: Required scan result file '{filepath}' is missing.", file=sys.stderr)
        return False
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        if data.get("schemaVersion") != "1.0":
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' schemaVersion is '{data.get('schemaVersion')}' (expected '1.0').", file=sys.stderr)
            return False

        status = data.get("status")
        if status not in allowed_statuses:
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' status is '{status}' (expected one of {allowed_statuses}).", file=sys.stderr)
            return False

        subject = data.get("subject", {})
        subj_digest = subject.get("digest")
        subj_role = subject.get("role")

        if subj_digest != expected_digest:
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' subject digest '{subj_digest}' does not match expected '{expected_digest}'.", file=sys.stderr)
            return False

        if subj_role != expected_role:
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' subject role '{subj_role}' does not match expected '{expected_role}'.", file=sys.stderr)
            return False

        scanner = data.get("scanner", {})
        if not scanner.get("name") or not scanner.get("version"):
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' is missing scanner metadata.", file=sys.stderr)
            return False

        if not data.get("startedAt") or not data.get("completedAt"):
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' is missing execution timestamps.", file=sys.stderr)
            return False

        wf_run_id = data.get("workflowRunId")
        if not wf_run_id:
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' is missing workflowRunId.", file=sys.stderr)
            return False

        if expected_run_id and expected_run_id != "local" and str(wf_run_id) != str(expected_run_id):
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' workflowRunId '{wf_run_id}' does not match expected '{expected_run_id}'.", file=sys.stderr)
            return False

        output_file = data.get("outputFile")
        output_hash = data.get("outputFileHash")
        if not output_file or not output_hash or not output_hash.startswith("sha256:"):
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' is missing valid outputFile or outputFileHash.", file=sys.stderr)
            return False

        if not os.path.exists(output_file):
            print(f"❌ DECISION ERROR: Referenced outputFile '{output_file}' in '{filepath}' does not exist.", file=sys.stderr)
            return False

        actual_output_hash = hash_file(output_file)
        if actual_output_hash != output_hash:
            print(f"❌ DECISION ERROR: Scan result file '{filepath}' outputFileHash '{output_hash}' does not match calculated '{actual_output_hash}' for '{output_file}'.", file=sys.stderr)
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

    created_at = datetime.now(timezone.utc).isoformat()
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    raw_id_seed = f"{args.app_promoted_digest}:{args.runner_promoted_digest}:{run_id}:{created_at}"
    decision_id = "dec-" + hashlib.sha256(raw_id_seed.encode("utf-8")).hexdigest()[:16]

    # Policy Hashes (Fail Closed)
    vuln_policy_hash = hash_file("policy/vulnerability-gate-policy.yml")
    ingestion_policy_hash = hash_file("policy/image-ingestion-policy.yml")
    license_policy_hash = hash_file("policy/license-policy.yml")
    runtime_policy_hash = hash_file("policy/runtime-hardening-policy.yml")

    if not vuln_policy_hash or not ingestion_policy_hash or not license_policy_hash or not runtime_policy_hash:
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

    # Strict Per-Image Result File Validation
    app_secret_valid = validate_result_file("app-secret-scan-result.json", args.app_source_digest, "application", expected_run_id=run_id)
    runner_secret_valid = validate_result_file("runner-secret-scan-result.json", args.runner_source_digest, "runner", expected_run_id=run_id)
    app_malware_valid = validate_result_file("app-malware-scan-result.json", args.app_source_digest, "application", expected_run_id=run_id)
    runner_malware_valid = validate_result_file("runner-malware-scan-result.json", args.runner_source_digest, "runner", expected_run_id=run_id)
    app_license_valid = validate_result_file("app-license-scan-result.json", args.app_source_digest, "application", expected_run_id=run_id)
    runner_license_valid = validate_result_file("runner-license-scan-result.json", args.runner_source_digest, "runner", expected_run_id=run_id)
    app_dast_valid = validate_result_file("app-dast-result.json", args.app_source_digest, "application", expected_run_id=run_id)
    app_runtime_valid = validate_result_file("app-runtime-result.json", args.app_source_digest, "application", expected_run_id=run_id)
    runner_runtime_valid = validate_result_file("runner-runtime-result.json", args.runner_source_digest, "runner", allowed_statuses={"EXEMPTED"}, expected_run_id=run_id)

    vuln_report_valid = os.path.exists("trivy-report.json") and os.path.exists("trivy-report.runner.json")
    sbom_valid = os.path.exists("sbom.spdx.json") and os.path.exists("runner-sbom.spdx.json")
    vex_valid = os.path.exists("app-vex.json") and os.path.exists("runner-vex.json")

    # Mandatory Named Evidence Set Completeness
    mandatory_evidence_files = [
        "app-secret-scan-result.json",
        "runner-secret-scan-result.json",
        "app-malware-scan-result.json",
        "runner-malware-scan-result.json",
        "app-license-scan-result.json",
        "runner-license-scan-result.json",
        "app-dast-result.json",
        "app-runtime-result.json",
        "runner-runtime-result.json",
        "trivy-report.json",
        "trivy-report.runner.json",
        "sbom.spdx.json",
        "runner-sbom.spdx.json",
        "app-vex.json",
        "runner-vex.json",
        "vendor-sig-check.txt",
        "transformation-attestation.json"
    ]

    for req_file in mandatory_evidence_files:
        if not os.path.exists(req_file):
            print(f"❌ DECISION ERROR: Mandatory evidence file '{req_file}' is missing from workspace.", file=sys.stderr)
            sys.exit(1)

    if args.decision == "PASS":
        if not (app_secret_valid and runner_secret_valid and app_malware_valid and runner_malware_valid and app_license_valid and runner_license_valid and app_dast_valid and app_runtime_valid and runner_runtime_valid and vuln_report_valid and sbom_valid and vex_valid):
            print("❌ DECISION ERROR: Decision is PASS but one or more required scan evidence files failed validation.", file=sys.stderr)
            sys.exit(1)

    # Structured Evidence Manifest
    manifest_entries = []
    for fpath in sorted(mandatory_evidence_files):
        info = file_info(fpath)
        if info:
            manifest_entries.append(info)

    manifest_doc = {"files": manifest_entries}
    manifest_json_bytes = json.dumps(manifest_doc, sort_keys=True).encode("utf-8")
    evidence_manifest_hash = f"sha256:{hashlib.sha256(manifest_json_bytes).hexdigest()}"

    with open("evidence-manifest.json", "w", encoding="utf-8") as f:
        f.write(json.dumps(manifest_doc, indent=2, sort_keys=True))

    # Fail Closed Waiver Validation (No synthetic defaults)
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
            risk_owner = w.get("risk_owner")
            remediation_owner = w.get("remediation_owner")
            remediation_ticket = w.get("remediation_ticket")
            env_scope = w.get("environment_scope")

            if not risk_owner or not isinstance(risk_owner, str):
                raise ValueError("Waiver must specify an explicit risk_owner.")
            if not remediation_owner or not isinstance(remediation_owner, str):
                raise ValueError("Waiver must specify an explicit remediation_owner.")
            if not remediation_ticket or not isinstance(remediation_ticket, str):
                raise ValueError("Waiver must specify an explicit remediation_ticket.")
            if not env_scope or not isinstance(env_scope, str):
                raise ValueError("Waiver must specify an explicit environment_scope.")

            if not accepted_cves or not isinstance(accepted_cves, list) or len(accepted_cves) == 0:
                raise ValueError("Waiver must contain a non-empty accepted_cves list.")

            if not expires_on or not isinstance(expires_on, str):
                raise ValueError("Waiver must contain an expires_on date string.")

            has_critical = False
            if os.path.exists("trivy-report.json"):
                with open("trivy-report.json", "r") as tf:
                    rep = json.load(tf)
                    for res in rep.get("Results", []):
                        for vuln in res.get("Vulnerabilities", []):
                            if vuln.get("VulnerabilityID") in accepted_cves and vuln.get("Severity") == "CRITICAL":
                                has_critical = True
                                break

            max_allowed_days = 14 if has_critical else 30
            exp_date = datetime.strptime(expires_on, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)

            if exp_date <= now_dt:
                raise ValueError(f"Waiver expiration date '{expires_on}' is in the past or expired.")

            days_valid = (exp_date - now_dt).days
            if days_valid > max_allowed_days:
                raise ValueError(f"Waiver duration ({days_valid} days) exceeds maximum policy limit of {max_allowed_days} days for this risk tier.")

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
        if args.waiver_file and os.path.exists(args.waiver_file):
            print(f"❌ DECISION ERROR: Decision is PASS but waiver file '{args.waiver_file}' was supplied.", file=sys.stderr)
            sys.exit(1)

    predicate = {
        "schemaVersion": "1.0",
        "decisionId": decision_id,
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
            "licensePolicyHash": license_policy_hash,
            "runtimePolicyHash": runtime_policy_hash
        },
        "evidence": {
            "vulnerabilityScanCompleted": vuln_report_valid,
            "secretScanCompleted": app_secret_valid and runner_secret_valid,
            "malwareScanCompleted": app_malware_valid and runner_malware_valid,
            "licenseScanCompleted": app_license_valid and runner_license_valid,
            "applicationRuntimeObservation": "PASSED" if app_runtime_valid else "FAILED",
            "runnerRuntimeObservation": "EXEMPTED",
            "runnerRuntimeExemption": {
                "status": "EXEMPTED",
                "exemption": {
                    "policyRule": "runtime.runner.exemption",
                    "policyHash": runtime_policy_hash,
                    "approvedBy": "security-team",
                    "riskOwner": "infrastructure-lead",
                    "reason": "Task runner dynamic observation exempt under security policy (isolated execution)",
                    "compensatingControls": [
                        "ephemeral_container_isolation",
                        "no_host_filesystem_mount"
                    ],
                    "reviewOn": "2026-08-01"
                }
            },
            "dastCompleted": app_dast_valid,
            "sbomGenerated": sbom_valid,
            "vexGenerated": vex_valid,
            "evidenceManifestHash": evidence_manifest_hash
        },
        "waiver": waiver_data,
        "workflow": {
            "runId": os.environ.get("GITHUB_RUN_ID", "local"),
            "workflowSha": os.environ.get("GITHUB_SHA", "unknown"),
            "repository": os.environ.get("GITHUB_REPOSITORY", "llody9977/artifactgate")
        },
        "toolVersions": tool_versions,
        "createdAt": created_at
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(predicate, f, indent=2)

    print(f"✅ Generated Promotion Decision Predicate: {args.output} (DecisionId: {decision_id}, Decision: {args.decision})")

if __name__ == "__main__":
    main()
