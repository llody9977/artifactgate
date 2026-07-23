#!/usr/bin/env python3
"""
ArtifactGate Normalized Evidence Builder
Merges all scanner reports into a canonical evidence.json object.
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timezone

def hash_file(filepath):
    if not os.path.exists(filepath):
        return None
    with open(filepath, "rb") as f:
        return f"sha256:{hashlib.sha256(f.read()).hexdigest()}"

def load_json(filepath):
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

def build_normalized_evidence(app_source_digest, runner_source_digest, app_promoted_digest=None, runner_promoted_digest=None, env_name="production"):
    run_id = os.environ.get("GITHUB_RUN_ID", "local")
    repo = os.environ.get("GITHUB_REPOSITORY", "llody9977/artifactgate")

    app_promoted = app_promoted_digest or app_source_digest
    runner_promoted = runner_promoted_digest or runner_source_digest

    # Scanner completion statuses
    scanner_status = {
        "vulnerability_app": {"completed": os.path.exists("trivy-report.json")},
        "vulnerability_runner": {"completed": os.path.exists("trivy-report.runner.json")},
        "secret_app": {"completed": os.path.exists("app-secret-scan-result.json")},
        "secret_runner": {"completed": os.path.exists("runner-secret-scan-result.json")},
        "malware_app": {"completed": os.path.exists("app-malware-scan-result.json")},
        "malware_runner": {"completed": os.path.exists("runner-malware-scan-result.json")},
        "license_app": {"completed": os.path.exists("app-license-scan-result.json")},
        "license_runner": {"completed": os.path.exists("runner-license-scan-result.json")},
        "sbom_app": {"completed": os.path.exists("sbom.spdx.json")},
        "sbom_runner": {"completed": os.path.exists("runner-sbom.spdx.json")},
        "runtime_app": {"completed": os.path.exists("app-runtime-result.json")},
    }

    # Policy hash verification
    vuln_policy_hash = hash_file("policy/vulnerability-gate-policy.yml")
    ingest_policy_hash = hash_file("policy/image-ingestion-policy.yml")
    license_policy_hash = hash_file("policy/license-policy.yml")
    runtime_policy_hash = hash_file("policy/runtime-hardening-policy.yml")

    scanner_status["policy_hash"] = {
        "verified": bool(vuln_policy_hash and ingest_policy_hash and license_policy_hash and runtime_policy_hash)
    }

    # Extract vulnerabilities
    vulnerabilities = []
    trivy_app = load_json("trivy-report.json") or {}
    for res in trivy_app.get("Results", []):
        for v in res.get("Vulnerabilities", []) or []:
            vulnerabilities.append({
                "id": v.get("VulnerabilityID", "UNKNOWN"),
                "severity": v.get("Severity", "UNKNOWN"),
                "in_kev": bool(v.get("InKEV") or v.get("GateDecision") in {"KEV_BLOCK", "BLOCK"}),
                "epss": float(v.get("EPSSScore") or 0.0),
                "age_days": int(v.get("CVEAgeDays") or 0),
                "vector": v.get("PrimaryVector", ""),
                "pkg_name": v.get("PkgName", "")
            })

    trivy_runner = load_json("trivy-report.runner.json") or {}
    for res in trivy_runner.get("Results", []):
        for v in res.get("Vulnerabilities", []) or []:
            vulnerabilities.append({
                "id": v.get("VulnerabilityID", "UNKNOWN"),
                "severity": v.get("Severity", "UNKNOWN"),
                "in_kev": bool(v.get("InKEV") or v.get("GateDecision") in {"KEV_BLOCK", "BLOCK"}),
                "epss": float(v.get("EPSSScore") or 0.0),
                "age_days": int(v.get("CVEAgeDays") or 0),
                "vector": v.get("PrimaryVector", ""),
                "pkg_name": v.get("PkgName", "")
            })

    # Extract licenses
    licenses = []
    lic_app = load_json("app-license-scan-output.json") or {}
    for res in lic_app.get("Results", []):
        for l in res.get("Licenses", []) or []:
            licenses.append({
                "component": l.get("PkgName") or l.get("Name", "unknown"),
                "license_id": l.get("LicenseID") or l.get("Name", "UNKNOWN")
            })

    # Extract secrets & malware
    secrets = []
    sec_app = load_json("app-secret-scan-result.json") or {}
    if sec_app.get("status") == "FAILED" or sec_app.get("findings"):
        secrets.append({"rule_id": "SECRET_DETECTED", "source": "app"})

    malware = []
    mal_app = load_json("app-malware-scan-result.json") or {}
    if mal_app.get("status") == "FAILED" or mal_app.get("findings"):
        malware.append({"signature": "MALWARE_DETECTED", "source": "app"})

    # Extract runtime statuses
    app_rt = load_json("app-runtime-result.json") or {}
    runner_rt = load_json("runner-runtime-result.json") or {}

    runtime_data = {
        "app_status": app_rt.get("status", "UNVERIFIED"),
        "runner_status": runner_rt.get("status", "EXEMPTED")
    }

    # Extract waivers/exceptions
    exceptions = []
    waiver = load_json("waiver.json")
    if waiver:
        exceptions.append({
            "exception_id": waiver.get("exception_id", "WAIVER-001"),
            "accepted_cves": waiver.get("accepted_cves", []),
            "expires_at": waiver.get("expires_on", "") + "T00:00:00Z" if waiver.get("expires_on") and "T" not in waiver.get("expires_on") else waiver.get("expires_on", ""),
            "approver": waiver.get("reviewer", waiver.get("approved_by", "security-team")),
            "justification": waiver.get("justification", "")
        })

    normalized = {
        "schemaVersion": "1.0",
        "artifact": {
            "application": {
                "source": "n8nio/n8n",
                "sourceDigest": app_source_digest,
                "promotedDigest": app_promoted
            },
            "runner": {
                "source": "n8nio/runners",
                "sourceDigest": runner_source_digest,
                "promotedDigest": runner_promoted
            },
            "platform": "linux/amd64"
        },
        "context": {
            "environment": env_name,
            "workflowRunId": str(run_id),
            "repository": repo
        },
        "evidence": {
            "vulnerabilities": vulnerabilities,
            "licenses": licenses,
            "secrets": secrets,
            "malware": malware,
            "sbom": {
                "application_generated": os.path.exists("sbom.spdx.json"),
                "runner_generated": os.path.exists("runner-sbom.spdx.json")
            },
            "runtime": runtime_data,
            "scanner_status": scanner_status
        },
        "exceptions": exceptions
    }

    return normalized

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 build_normalized_evidence.py <app-source-digest> <runner-source-digest> [app-promoted-digest] [runner-promoted-digest]")
        sys.exit(1)

    app_src = sys.argv[1]
    runner_src = sys.argv[2]
    app_prom = sys.argv[3] if len(sys.argv) > 3 else app_src
    runner_prom = sys.argv[4] if len(sys.argv) > 4 else runner_src

    ev = build_normalized_evidence(app_src, runner_src, app_prom, runner_prom)
    with open("evidence.json", "w", encoding="utf-8") as f:
        json.dump(ev, f, indent=2)

    print(f"✅ Normalized evidence object generated: evidence.json ({len(ev['evidence']['vulnerabilities'])} CVEs, {len(ev['evidence']['licenses'])} licenses).")
