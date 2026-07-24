#!/usr/bin/env python3
"""
Test Suite for ArtifactGate Security Review Remediations
"""

import os
import sys
import json
import tempfile
import unittest
import hashlib
from datetime import datetime, timezone, timedelta

# Add parent directory to path so we can import scripts
sys.path.insert(0, os.path.dirname(__file__))

from validate_promotion_decision import validate_predicate
from validate_vex import validate_vex
from validate_sbom import validate_sbom

def sha256_of(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"

class TestSecurityRemediations(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.tmp_dir.name)

        # Create dummy policy files
        os.makedirs("policy", exist_ok=True)
        with open("policy/vulnerability-gate-policy.yml", "w") as f:
            f.write("test_vuln_policy: 1\n")
        with open("policy/image-ingestion-policy.yml", "w") as f:
            f.write("test_ingestion_policy: 1\n")
        with open("policy/license-policy.yml", "w") as f:
            f.write("deny:\n  - GPL-3.0\nmanual_review:\n  - AGPL-3.0\n")
        with open("policy/runtime-hardening-policy.yml", "w") as f:
            f.write("runner_exemption:\n  rule_id: runtime.runner.exemption\n")

        self.vuln_hash = sha256_of("policy/vulnerability-gate-policy.yml")
        self.ingest_hash = sha256_of("policy/image-ingestion-policy.yml")
        self.lic_hash = sha256_of("policy/license-policy.yml")
        self.runtime_hash = sha256_of("policy/runtime-hardening-policy.yml")

    def tearDown(self):
        os.chdir(self.old_cwd)
        self.tmp_dir.cleanup()

    def test_policy_hash_and_exemption_validation(self):
        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).strftime("%Y-%m-%d")
        predicate = {
            "schemaVersion": "1.0",
            "decisionId": "dec-1234567890abcdef",
            "decision": "PASS",
            "application": {
                "source": "n8nio/n8n",
                "sourceDigest": "sha256:appsrc123",
                "promotedDigest": "sha256:appprom123"
            },
            "runner": {
                "source": "n8nio/runners",
                "sourceDigest": "sha256:runsrc123",
                "promotedDigest": "sha256:runprom123"
            },
            "platform": "linux/amd64",
            "policy": {
                "repository": "llody9977/artifactgate",
                "commit": "abc1234",
                "vulnerabilityPolicyHash": self.vuln_hash,
                "ingestionPolicyHash": self.ingest_hash,
                "licensePolicyHash": self.lic_hash,
                "runtimePolicyHash": self.runtime_hash
            },
            "evidence": {
                "vulnerabilityScanCompleted": True,
                "secretScanCompleted": True,
                "malwareScanCompleted": True,
                "licenseScanCompleted": True,
                "applicationRuntimeObservation": "PASSED",
                "runnerRuntimeObservation": "EXEMPTED",
                "runnerRuntimeExemption": {
                    "status": "EXEMPTED",
                    "exemption": {
                        "policyRule": "runtime.runner.exemption",
                        "policyHash": self.runtime_hash,
                        "approvedBy": "security-team",
                        "riskOwner": "infrastructure-lead",
                        "reason": "Task runner dynamic observation exempt under security policy",
                        "compensatingControls": ["isolation"],
                        "reviewOn": future_date
                    }
                },
                "dastCompleted": True,
                "sbomGenerated": True,
                "vexGenerated": True,
                "evidenceManifestHash": "sha256:manifest123"
            },
            "waiver": {"present": False},
            "workflow": {
                "runId": "12345",
                "workflowSha": "abc1234",
                "repository": "llody9977/artifactgate"
            },
            "createdAt": "2026-07-23T00:00:00Z"
        }

        with open("predicate.json", "w") as f:
            json.dump(predicate, f)

        self.assertTrue(validate_predicate(
            "predicate.json",
            expected_app_promoted_digest="sha256:appprom123",
            expected_runner_promoted_digest="sha256:runprom123",
            expected_repository="llody9977/artifactgate"
        ))

        # Tampered policy hash should fail
        predicate_tampered = json.loads(json.dumps(predicate))
        predicate_tampered["policy"]["vulnerabilityPolicyHash"] = "sha256:tamperedhash"
        with open("predicate_tampered.json", "w") as f:
            json.dump(predicate_tampered, f)

        self.assertFalse(validate_predicate(
            "predicate_tampered.json",
            expected_app_promoted_digest="sha256:appprom123",
            expected_runner_promoted_digest="sha256:runprom123",
            expected_repository="llody9977/artifactgate"
        ))

    def test_validate_vex(self):
        vex_doc = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://example.com/vex/1",
            "author": "artifactgate-pipeline",
            "timestamp": "2026-07-23T00:00:00Z",
            "version": 1,
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2026-1234"},
                    "products": [{"@id": "pkg:oci/n8n@sha256:appdigest123?repository_url=..."}],
                    "status": "not_affected",
                    "justification": "code_not_present",
                    "timestamp": "2026-07-23T00:00:00Z"
                }
            ]
        }
        with open("vex.json", "w") as f:
            json.dump(vex_doc, f)

        self.assertTrue(validate_vex("vex.json", expected_digest="sha256:appdigest123"))

        # Missing timestamp should fail
        bad_vex = json.loads(json.dumps(vex_doc))
        del bad_vex["timestamp"]
        with open("bad_vex.json", "w") as f:
            json.dump(bad_vex, f)
        self.assertFalse(validate_vex("bad_vex.json", expected_digest="sha256:appdigest123"))

        # Test VEX statement status 'affected' without matching waiver fails
        vex_affected = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://example.com/vex/2",
            "author": "artifactgate-pipeline",
            "timestamp": "2026-07-23T00:00:00Z",
            "version": 1,
            "statements": [
                {
                    "vulnerability": {"name": "CVE-2026-9999"},
                    "products": [{"@id": "pkg:oci/n8n@sha256:appdigest123?repository_url=..."}],
                    "status": "affected",
                    "timestamp": "2026-07-23T00:00:00Z"
                }
            ]
        }
        with open("vex_affected.json", "w") as f:
            json.dump(vex_affected, f)

        # Non-existent or inactive waiver should fail for 'affected' status
        self.assertFalse(validate_vex("vex_affected.json", expected_digest="sha256:appdigest123", waiver_path="nonexistent-waiver.json"))

        # Active waiver containing CVE-2026-9999 should pass
        future_date = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%d")
        waiver_data = {
            "accepted_cves": ["CVE-2026-9999"],
            "expires_on": future_date,
            "reviewer": "security-team",
            "justification": "Mitigated by network boundary controls"
        }
        with open("waiver.json", "w") as f:
            json.dump(waiver_data, f)

        self.assertTrue(validate_vex("vex_affected.json", expected_digest="sha256:appdigest123", waiver_path="waiver.json"))


    def test_validate_sbom(self):
        sbom_doc = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "n8n-sbom",
            "documentNamespace": "https://github.com/llody9977/artifactgate/sbom/sha256:appdigest123",
            "creationInfo": {
                "creators": ["Tool: Trivy-0.58.2"]
            },
            "packages": [
                {
                    "name": f"pkg_{i}",
                    "SPDXID": f"SPDXRef-Package-{i}",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "appdigest123"}] if i == 0 else []
                } for i in range(12)
            ]
        }
        with open("sbom.spdx.json", "w") as f:
            json.dump(sbom_doc, f)

        self.assertTrue(validate_sbom("sbom.spdx.json", target_digest="sha256:appdigest123", min_package_count=10))

        # Unbound target digest should fail
        self.assertFalse(validate_sbom("sbom.spdx.json", target_digest="sha256:unbounddigest999", min_package_count=10))

if __name__ == "__main__":
    unittest.main()
