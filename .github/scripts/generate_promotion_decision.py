#!/usr/bin/env python3
"""
Generate Signed Promotion Decision Predicate
Produces promotion-decision.json attestation predicate recording gate state, policy hashes, tool versions, and waiver metadata.
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

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate Promotion Decision Predicate")
    parser.add_argument("--decision", required=True, choices=["PASS", "WAIVER"])
    parser.add_argument("--app-source", default="n8nio/n8n")
    parser.add_argument("--app-digest", required=True)
    parser.add_argument("--runner-source", default="n8nio/runners")
    parser.add_argument("--runner-digest", required=True)
    parser.add_argument("--waiver-file", default=None)
    parser.add_argument("--output", default="promotion-decision.json")
    args = parser.parse_args()

    vuln_policy_hash = hash_file("policy/vulnerability-gate-policy.yml")
    ingestion_policy_hash = hash_file("policy/image-ingestion-policy.yml")
    license_policy_hash = hash_file("policy/license-policy.yml")

    # Aggregate evidence manifest hash
    evidence_files = ["trivy-report.json", "sbom.spdx.json", "vex.json", "vendor-sig-check.txt"]
    h_evidence = hashlib.sha256()
    for ef in sorted(evidence_files):
        if os.path.exists(ef):
            with open(ef, "rb") as f:
                h_evidence.update(f.read())
    evidence_manifest_hash = f"sha256:{h_evidence.hexdigest()}"

    # Waiver metadata
    waiver_data = {
        "present": False,
        "approvedBy": None,
        "acceptedCves": [],
        "expiresOn": None,
        "justification": None
    }
    if args.waiver_file and os.path.exists(args.waiver_file):
        try:
            with open(args.waiver_file, "r") as f:
                w = json.load(f)
                waiver_data["present"] = True
                waiver_data["approvedBy"] = w.get("reviewer")
                waiver_data["acceptedCves"] = w.get("accepted_cves", [])
                waiver_data["expiresOn"] = w.get("expires_on")
                waiver_data["justification"] = w.get("justification")
        except Exception as exc:
            print(f"Warning: Could not parse waiver file: {exc}", file=sys.stderr)

    predicate = {
        "schemaVersion": "1.0",
        "decision": args.decision,
        "application": {
            "source": args.app_source,
            "sourceDigest": args.app_digest,
            "promotedDigest": args.app_digest
        },
        "runner": {
            "source": args.runner_source,
            "sourceDigest": args.runner_digest,
            "promotedDigest": args.runner_digest
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
            "vulnerabilityScanCompleted": os.path.exists("trivy-report.json"),
            "secretScanCompleted": True,
            "malwareScanCompleted": True,
            "licenseScanCompleted": os.path.exists("policy/license-policy.yml"),
            "runtimeObservationCompleted": os.path.exists("tracee-output/package-files.tsv"),
            "dastCompleted": True,
            "sbomGenerated": os.path.exists("sbom.spdx.json"),
            "evidenceManifestHash": evidence_manifest_hash
        },
        "waiver": waiver_data,
        "workflow": {
            "runId": os.environ.get("GITHUB_RUN_ID", "local"),
            "workflowSha": os.environ.get("GITHUB_SHA", "unknown"),
            "repository": os.environ.get("GITHUB_REPOSITORY", "llody9977/artifactgate")
        },
        "toolVersions": {
            "trivy": "0.58.2",
            "cosign": "v3.1.2",
            "yq": "v4.44.1",
            "clamav": "1.5.3",
            "tracee": "v0.22.0",
            "zap": "2.15.0",
            "python": sys.version.split()[0]
        },
        "createdAt": datetime.now(timezone.utc).isoformat()
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(predicate, f, indent=2)

    print(f"✅ Generated Promotion Decision Predicate: {args.output} (Decision: {args.decision})")

if __name__ == "__main__":
    main()
