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

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate Promotion Decision Predicate")
    parser.add_argument("--decision", required=True, choices=["PASS", "WAIVER"])
    parser.add_argument("--app-source", default="n8nio/n8n")
    parser.add_argument("--app-digest", required=True)
    parser.add_argument("--runner-source", default="n8nio/runners")
    parser.add_argument("--runner-digest", required=True)
    parser.add_argument("--waiver-file", default=None)
    parser.add_argument("--tool-versions-file", default=None)
    parser.add_argument("--output", default="promotion-decision.json")
    args = parser.parse_args()

    vuln_policy_hash = hash_file("policy/vulnerability-gate-policy.yml")
    ingestion_policy_hash = hash_file("policy/image-ingestion-policy.yml")
    license_policy_hash = hash_file("policy/license-policy.yml")

    # Require policy files to exist and be hashed
    if not vuln_policy_hash or not ingestion_policy_hash or not license_policy_hash:
        print("❌ DECISION ERROR: One or more required policy files are missing or unreadable.", file=sys.stderr)
        sys.exit(1)

    # Structured Evidence Manifest
    evidence_candidate_files = [
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
    for fpath in sorted(evidence_candidate_files):
        info = file_info(fpath)
        if info:
            manifest_entries.append(info)

    manifest_doc = {"files": manifest_entries}
    manifest_json_bytes = json.dumps(manifest_doc, sort_keys=True).encode("utf-8")
    evidence_manifest_hash = f"sha256:{hashlib.sha256(manifest_json_bytes).hexdigest()}"

    with open("evidence-manifest.json", "w", encoding="utf-8") as f:
        f.write(json.dumps(manifest_doc, indent=2, sort_keys=True))

    # Fail Closed Waiver Validation
    waiver_data = {
        "present": False,
        "approvedBy": None,
        "acceptedCves": [],
        "expiresOn": None,
        "justification": None
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

            if not accepted_cves or not isinstance(accepted_cves, list) or len(accepted_cves) == 0:
                raise ValueError("Waiver must contain a non-empty accepted_cves list.")

            if not expires_on or not isinstance(expires_on, str):
                raise ValueError("Waiver must contain an expires_on date string.")

            # Validate future expiry
            exp_date = datetime.strptime(expires_on, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            if exp_date <= datetime.now(timezone.utc):
                raise ValueError(f"Waiver expiration date '{expires_on}' is in the past or expired.")

            if not reviewer or not isinstance(reviewer, str):
                raise ValueError("Waiver must specify a reviewer.")

            if not justification or not isinstance(justification, str) or len(justification.strip()) < 10:
                raise ValueError("Waiver must contain a detailed justification (min 10 chars).")

            waiver_data["present"] = True
            waiver_data["approvedBy"] = reviewer
            waiver_data["acceptedCves"] = accepted_cves
            waiver_data["expiresOn"] = expires_on
            waiver_data["justification"] = justification
        except Exception as exc:
            print(f"❌ DECISION ERROR: Failed to validate waiver file '{args.waiver_file}': {exc}", file=sys.stderr)
            sys.exit(1)
    else:
        # Decision is PASS — waiver must NOT be present
        if args.waiver_file and os.path.exists(args.waiver_file):
            print(f"❌ DECISION ERROR: Decision is PASS but waiver file '{args.waiver_file}' was supplied.", file=sys.stderr)
            sys.exit(1)

    # Dynamic Tool Versions
    tool_versions = {
        "trivy": "0.58.2",
        "cosign": "v3.1.2",
        "yq": "v4.44.1",
        "clamav": "1.5.3@sha256:7f5389ccaa2368c383fa80e167ccfe44348d71e685f926fce4755eed1757673a",
        "tracee": "v0.22.0",
        "zap": "2.15.0",
        "python": sys.version.split()[0]
    }
    if args.tool_versions_file and os.path.exists(args.tool_versions_file):
        try:
            with open(args.tool_versions_file, "r") as f:
                tv = json.load(f)
                if isinstance(tv, dict):
                    tool_versions.update(tv)
        except Exception as exc:
            print(f"Warning: Could not parse tool versions file: {exc}", file=sys.stderr)

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
            "secretScanCompleted": os.path.exists("secret-scan-result.json"),
            "malwareScanCompleted": os.path.exists("malware-scan-result.json"),
            "licenseScanCompleted": os.path.exists("license-scan-result.json"),
            "runtimeObservationCompleted": os.path.exists("runtime-result.json") or os.path.exists("tracee-output/package-files.tsv"),
            "dastCompleted": os.path.exists("dast-result.json") or os.path.exists("tracee-output/zap-report.html"),
            "sbomGenerated": os.path.exists("sbom.spdx.json") and os.path.exists("runner-sbom.spdx.json"),
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
