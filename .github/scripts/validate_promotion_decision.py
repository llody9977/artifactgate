#!/usr/bin/env python3
"""
Semantic Promotion Decision Attestation Validator
Validates promotiondecision predicates for schema compliance, 4-digest consistency, policy hash integrity, evidence manifest validation, waiver constraints, and decisionId matching.
"""

import sys
import json
import os
import argparse
from datetime import datetime, timezone

def validate_predicate(predicate_path, expected_app_promoted_digest, expected_runner_promoted_digest, expected_repository=None, expected_platform="linux/amd64", expected_decision_id=None):
    if not os.path.exists(predicate_path):
        print(f"❌ ADMISSION ERROR: Predicate file '{predicate_path}' does not exist.", file=sys.stderr)
        return False

    try:
        with open(predicate_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as exc:
        print(f"❌ ADMISSION ERROR: Failed to parse predicate JSON in '{predicate_path}': {exc}", file=sys.stderr)
        return False

    if not isinstance(data, dict):
        print(f"❌ ADMISSION ERROR: Predicate root must be a JSON object in '{predicate_path}'.", file=sys.stderr)
        return False

    if data.get("schemaVersion") != "1.0":
        print(f"❌ ADMISSION ERROR: Unsupported predicate schemaVersion '{data.get('schemaVersion')}'. Expected '1.0'.", file=sys.stderr)
        return False

    decision_id = data.get("decisionId")
    if not decision_id or not isinstance(decision_id, str) or not decision_id.startswith("dec-"):
        print(f"❌ ADMISSION ERROR: Missing or invalid decisionId '{decision_id}'.", file=sys.stderr)
        return False

    if expected_decision_id and decision_id != expected_decision_id:
        print(f"❌ ADMISSION ERROR: decisionId '{decision_id}' does not match expected '{expected_decision_id}'.", file=sys.stderr)
        return False

    decision = data.get("decision")
    if decision not in ["PASS", "WAIVER"]:
        print(f"❌ ADMISSION ERROR: Invalid decision '{decision}'. Expected 'PASS' or 'WAIVER'.", file=sys.stderr)
        return False

    platform = data.get("platform")
    if platform != expected_platform:
        print(f"❌ ADMISSION ERROR: Platform '{platform}' does not match expected '{expected_platform}'.", file=sys.stderr)
        return False

    policy = data.get("policy", {})
    repo = policy.get("repository") or data.get("workflow", {}).get("repository")
    if expected_repository and repo != expected_repository:
        print(f"❌ ADMISSION ERROR: Workflow repository '{repo}' does not match expected '{expected_repository}'.", file=sys.stderr)
        return False

    # 4-Digest Validation
    app = data.get("application", {})
    runner = data.get("runner", {})

    app_promoted = app.get("promotedDigest")
    runner_promoted = runner.get("promotedDigest")
    app_source = app.get("sourceDigest")
    runner_source = runner.get("sourceDigest")

    if not app_source or not app_source.startswith("sha256:"):
        print("❌ ADMISSION ERROR: Missing or invalid application sourceDigest.", file=sys.stderr)
        return False

    if not runner_source or not runner_source.startswith("sha256:"):
        print("❌ ADMISSION ERROR: Missing or invalid runner sourceDigest.", file=sys.stderr)
        return False

    if app_promoted != expected_app_promoted_digest:
        print(f"❌ ADMISSION ERROR: Application promoted digest '{app_promoted}' does not match expected '{expected_app_promoted_digest}'.", file=sys.stderr)
        return False

    if runner_promoted != expected_runner_promoted_digest:
        print(f"❌ ADMISSION ERROR: Runner promoted digest '{runner_promoted}' does not match expected '{expected_runner_promoted_digest}'.", file=sys.stderr)
        return False

    # Policy Hashes
    for p_key in ["vulnerabilityPolicyHash", "ingestionPolicyHash", "licensePolicyHash"]:
        p_val = policy.get(p_key)
        if not p_val or not str(p_val).startswith("sha256:"):
            print(f"❌ ADMISSION ERROR: Missing or invalid policy hash '{p_key}' in predicate.", file=sys.stderr)
            return False

    # Evidence Completion Flags & Explicit Runtime Statuses
    evidence = data.get("evidence", {})
    req_booleans = [
        "vulnerabilityScanCompleted",
        "secretScanCompleted",
        "malwareScanCompleted",
        "licenseScanCompleted",
        "dastCompleted",
        "sbomGenerated",
        "vexGenerated"
    ]
    for b_key in req_booleans:
        if evidence.get(b_key) is not True:
            print(f"❌ ADMISSION ERROR: Mandatory evidence flag '{b_key}' is not True in predicate.", file=sys.stderr)
            return False

    app_rt = evidence.get("applicationRuntimeObservation")
    run_rt = evidence.get("runnerRuntimeObservation")
    if app_rt != "PASSED":
        print(f"❌ ADMISSION ERROR: Application runtime observation status '{app_rt}' is not 'PASSED'.", file=sys.stderr)
        return False
    if run_rt != "EXEMPTED":
        print(f"❌ ADMISSION ERROR: Runner runtime observation status '{run_rt}' is not 'EXEMPTED'.", file=sys.stderr)
        return False

    manifest_hash = evidence.get("evidenceManifestHash")
    if not manifest_hash or not str(manifest_hash).startswith("sha256:"):
        print(f"❌ ADMISSION ERROR: Missing or invalid evidenceManifestHash '{manifest_hash}'.", file=sys.stderr)
        return False

    # Waiver Verification
    waiver = data.get("waiver", {})
    waiver_present = waiver.get("present", False)

    if decision == "PASS":
        if waiver_present:
            print("❌ ADMISSION ERROR: Decision is PASS but waiver is marked present.", file=sys.stderr)
            return False
    elif decision == "WAIVER":
        if not waiver_present:
            print("❌ ADMISSION ERROR: Decision is WAIVER but waiver.present is False.", file=sys.stderr)
            return False

        reviewer = waiver.get("approvedBy")
        justification = waiver.get("justification")
        accepted_cves = waiver.get("acceptedCves")
        expires_on = waiver.get("expiresOn")
        risk_owner = waiver.get("riskOwner")
        remediation_owner = waiver.get("remediationOwner")
        remediation_ticket = waiver.get("remediationTicket")
        env_scope = waiver.get("environmentScope")

        if not reviewer or not justification or not accepted_cves or not expires_on:
            print("❌ ADMISSION ERROR: Waiver is missing mandatory fields.", file=sys.stderr)
            return False

        if not risk_owner or not remediation_owner or not remediation_ticket or not env_scope:
            print("❌ ADMISSION ERROR: Waiver is missing explicit governance metadata (riskOwner, remediationOwner, remediationTicket, environmentScope).", file=sys.stderr)
            return False

        try:
            exp_date = datetime.strptime(expires_on, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            if exp_date <= now_dt:
                print(f"❌ ADMISSION ERROR: Waiver expiration date '{expires_on}' is in the past.", file=sys.stderr)
                return False
            days_valid = (exp_date - now_dt).days
            if days_valid > 30:
                print(f"❌ ADMISSION ERROR: Waiver duration ({days_valid} days) exceeds maximum policy limit of 30 days.", file=sys.stderr)
                return False
        except Exception as exc:
            print(f"❌ ADMISSION ERROR: Failed to parse waiver expiration date '{expires_on}': {exc}", file=sys.stderr)
            return False

    print(f"✅ Semantic Admission Decision Validation PASSED (DecisionId: {decision_id}, Decision: {decision}, Repository: {repo}, Platform: {platform}).")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate Promotion Decision Predicate")
    parser.add_argument("--predicate-file", required=True)
    parser.add_argument("--expected-app-promoted-digest", required=True)
    parser.add_argument("--expected-runner-promoted-digest", required=True)
    parser.add_argument("--expected-repository", default=None)
    parser.add_argument("--expected-platform", default="linux/amd64")
    parser.add_argument("--expected-decision-id", default=None)
    args = parser.parse_args()

    if not validate_predicate(
        args.predicate_file,
        args.expected_app_promoted_digest,
        args.expected_runner_promoted_digest,
        args.expected_repository,
        args.expected_platform,
        args.expected_decision_id
    ):
        sys.exit(1)
