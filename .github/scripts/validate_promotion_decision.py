#!/usr/bin/env python3
"""
Semantic Promotion Decision Attestation Validator
Enforces complete admission validation of promotion-decision.json predicates against target deployment parameters, policy hashes, evidence completion, and waiver constraints.
"""

import sys
import json
import os
import hashlib
from datetime import datetime, timezone

def hash_file(filepath):
    if not os.path.exists(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"

def validate_decision(predicate, expected_app_promoted, expected_runner_promoted, expected_repo, expected_platform="linux/amd64", expected_app_source=None, expected_runner_source=None):
    if not isinstance(predicate, dict):
        print("❌ ADMISSION ERROR: Predicate is not a valid JSON dictionary.", file=sys.stderr)
        return False

    # 1. Schema & Platform Checks
    schema_ver = predicate.get("schemaVersion")
    if schema_ver != "1.0":
        print(f"❌ ADMISSION ERROR: Unsupported schemaVersion '{schema_ver}'. Expected '1.0'.", file=sys.stderr)
        return False

    decision = predicate.get("decision")
    if decision not in ["PASS", "WAIVER"]:
        print(f"❌ ADMISSION ERROR: Invalid decision '{decision}'. Expected 'PASS' or 'WAIVER'.", file=sys.stderr)
        return False

    platform = predicate.get("platform")
    if platform != expected_platform:
        print(f"❌ ADMISSION ERROR: Target platform mismatch '{platform}'. Expected '{expected_platform}'.", file=sys.stderr)
        return False

    repo = predicate.get("workflow", {}).get("repository") or predicate.get("policy", {}).get("repository")
    if repo != expected_repo:
        print(f"❌ ADMISSION ERROR: Repository mismatch '{repo}'. Expected '{expected_repo}'.", file=sys.stderr)
        return False

    # 2. Exact 4-Digest Matching Checks
    app_data = predicate.get("application", {})
    runner_data = predicate.get("runner", {})

    app_promoted = app_data.get("promotedDigest")
    runner_promoted = runner_data.get("promotedDigest")

    if app_promoted != expected_app_promoted:
        print(f"❌ ADMISSION ERROR: Application promoted digest mismatch in predicate ('{app_promoted}' vs expected '{expected_app_promoted}').", file=sys.stderr)
        return False

    if runner_promoted != expected_runner_promoted:
        print(f"❌ ADMISSION ERROR: Runner promoted digest mismatch in predicate ('{runner_promoted}' vs expected '{expected_runner_promoted}').", file=sys.stderr)
        return False

    if expected_app_source and app_data.get("sourceDigest") != expected_app_source:
        print(f"❌ ADMISSION ERROR: Application source digest mismatch in predicate ('{app_data.get('sourceDigest')}' vs expected '{expected_app_source}').", file=sys.stderr)
        return False

    if expected_runner_source and runner_data.get("sourceDigest") != expected_runner_source:
        print(f"❌ ADMISSION ERROR: Runner source digest mismatch in predicate ('{runner_data.get('sourceDigest')}' vs expected '{expected_runner_source}').", file=sys.stderr)
        return False

    # 3. Policy Hash Verification
    policy = predicate.get("policy", {})
    for pkey, path in [("vulnerabilityPolicyHash", "policy/vulnerability-gate-policy.yml"),
                       ("ingestionPolicyHash", "policy/image-ingestion-policy.yml"),
                       ("licensePolicyHash", "policy/license-policy.yml")]:
        phash = policy.get(pkey)
        if not phash or not phash.startswith("sha256:") or len(phash) != 71:
            print(f"❌ ADMISSION ERROR: Missing or invalid policy hash '{pkey}': '{phash}'.", file=sys.stderr)
            return False

        if os.path.exists(path):
            local_hash = hash_file(path)
            if local_hash and phash != local_hash:
                print(f"❌ ADMISSION ERROR: Policy hash mismatch for '{path}' (predicate '{phash}' vs local '{local_hash}').", file=sys.stderr)
                return False

    # 4. Evidence Completion Checks
    evidence = predicate.get("evidence", {})
    required_flags = [
        "vulnerabilityScanCompleted",
        "secretScanCompleted",
        "malwareScanCompleted",
        "licenseScanCompleted",
        "runtimeObservationCompleted",
        "dastCompleted",
        "sbomGenerated"
    ]
    for flag in required_flags:
        if evidence.get(flag) is not True:
            print(f"❌ ADMISSION ERROR: Evidence requirement '{flag}' is not True in predicate.", file=sys.stderr)
            return False

    manifest_hash = evidence.get("evidenceManifestHash")
    if not manifest_hash or not manifest_hash.startswith("sha256:") or len(manifest_hash) != 71:
        print(f"❌ ADMISSION ERROR: Missing or malformed evidenceManifestHash in predicate: '{manifest_hash}'.", file=sys.stderr)
        return False

    # 5. Waiver Verification
    waiver = predicate.get("waiver", {})
    waiver_present = waiver.get("present")

    if decision == "WAIVER":
        if waiver_present is not True:
            print("❌ ADMISSION ERROR: Decision is WAIVER but waiver.present is not True.", file=sys.stderr)
            return False

        expires_on = waiver.get("expiresOn")
        if not expires_on:
            print("❌ ADMISSION ERROR: Waiver is missing expiresOn date.", file=sys.stderr)
            return False

        try:
            exp_dt = datetime.strptime(expires_on, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if exp_dt <= datetime.now(timezone.utc):
                print(f"❌ ADMISSION ERROR: Waiver expiration date '{expires_on}' has expired.", file=sys.stderr)
                return False
        except Exception as exc:
            print(f"❌ ADMISSION ERROR: Invalid waiver expiresOn date format '{expires_on}': {exc}", file=sys.stderr)
            return False

        if not waiver.get("acceptedCves") or not isinstance(waiver.get("acceptedCves"), list) or len(waiver.get("acceptedCves")) == 0:
            print("❌ ADMISSION ERROR: Waiver acceptedCves list is missing or empty.", file=sys.stderr)
            return False

        if not waiver.get("approvedBy"):
            print("❌ ADMISSION ERROR: Waiver approvedBy reviewer is missing.", file=sys.stderr)
            return False

        if not waiver.get("justification") or len(str(waiver.get("justification")).strip()) < 10:
            print("❌ ADMISSION ERROR: Waiver justification is missing or inadequate.", file=sys.stderr)
            return False
    else:
        if waiver_present is True:
            print("❌ ADMISSION ERROR: Decision is PASS but waiver.present is True.", file=sys.stderr)
            return False

    print(f"✅ Semantic Admission Decision Validation PASSED (Decision: {decision}, Repository: {repo}, Platform: {platform}).")
    return True

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Validate Promotion Decision Attestation Predicate")
    parser.add_argument("--predicate-file", required=True, help="Path to decoded JSON predicate file")
    parser.add_argument("--expected-app-promoted-digest", required=True, help="Expected application GHCR digest")
    parser.add_argument("--expected-runner-promoted-digest", required=True, help="Expected runner GHCR digest")
    parser.add_argument("--expected-repository", required=True, help="Expected repository (e.g. llody9977/artifactgate)")
    parser.add_argument("--expected-platform", default="linux/amd64")
    parser.add_argument("--expected-app-source-digest", default=None)
    parser.add_argument("--expected-runner-source-digest", default=None)

    args = parser.parse_args()

    if not os.path.exists(args.predicate_file):
        print(f"❌ ADMISSION ERROR: Predicate file '{args.predicate_file}' does not exist.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(args.predicate_file, "r", encoding="utf-8") as f:
            predicate = json.load(f)
    except Exception as exc:
        print(f"❌ ADMISSION ERROR: Failed to parse predicate JSON file '{args.predicate_file}': {exc}", file=sys.stderr)
        sys.exit(1)

    ok = validate_decision(
        predicate,
        expected_app_promoted=args.expected_app_promoted_digest,
        expected_runner_promoted=args.expected_runner_promoted_digest,
        expected_repo=args.expected_repository,
        expected_platform=args.expected_platform,
        expected_app_source=args.expected_app_source_digest,
        expected_runner_source=args.expected_runner_source_digest
    )

    if not ok:
        sys.exit(1)

if __name__ == "__main__":
    main()
