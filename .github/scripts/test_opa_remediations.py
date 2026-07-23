#!/usr/bin/env python3
"""
Test Suite for ArtifactGate OPA Policy-as-Code Integration
"""

import os
import sys
import json
import tempfile
import unittest
import subprocess
from datetime import datetime, timezone, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(__file__))

from build_normalized_evidence import build_normalized_evidence
from evaluate_opa_policy import evaluate_and_generate_decision
from validate_promotion_decision import validate_predicate

class TestOPAPolicyIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.old_cwd = os.getcwd()
        os.chdir(self.tmp_dir.name)

        # Copy policy directory structure into temp dir for testing
        src_policy = os.path.join(self.old_cwd, "policy")
        if os.path.exists(src_policy):
            subprocess.run(["cp", "-r", src_policy, "."], check=True)

        # Create dummy evidence files
        with open("app-secret-scan-result.json", "w") as f: json.dump({"status": "PASSED"}, f)
        with open("runner-secret-scan-result.json", "w") as f: json.dump({"status": "PASSED"}, f)
        with open("app-malware-scan-result.json", "w") as f: json.dump({"status": "PASSED"}, f)
        with open("runner-malware-scan-result.json", "w") as f: json.dump({"status": "PASSED"}, f)
        with open("app-license-scan-result.json", "w") as f: json.dump({"status": "PASSED"}, f)
        with open("runner-license-scan-result.json", "w") as f: json.dump({"status": "PASSED"}, f)
        with open("app-dast-result.json", "w") as f: json.dump({"status": "PASSED"}, f)
        with open("app-runtime-result.json", "w") as f: json.dump({"status": "PASSED"}, f)
        with open("runner-runtime-result.json", "w") as f: json.dump({"status": "EXEMPTED"}, f)
        with open("trivy-report.json", "w") as f: json.dump({"Results": []}, f)
        with open("trivy-report.runner.json", "w") as f: json.dump({"Results": []}, f)
        with open("sbom.spdx.json", "w") as f: json.dump({"spdxVersion": "SPDX-2.3"}, f)
        with open("runner-sbom.spdx.json", "w") as f: json.dump({"spdxVersion": "SPDX-2.3"}, f)
        with open("app-vex.json", "w") as f: json.dump({"@context": "openvex"}, f)
        with open("runner-vex.json", "w") as f: json.dump({"@context": "openvex"}, f)

    def tearDown(self):
        os.chdir(self.old_cwd)
        self.tmp_dir.cleanup()

    def test_rego_unit_tests(self):
        opa_bin = "/tmp/opa" if os.path.exists("/tmp/opa") else "opa"
        res = subprocess.run([opa_bin, "test", "policy/artifactgate/", "policy/data/", "policy/tests/"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, f"Rego unit tests failed: {res.stderr}\n{res.stdout}")
        self.assertIn("PASS: 8/8", res.stdout)

    def test_normalized_evidence_building(self):
        ev = build_normalized_evidence("sha256:appsrc123", "sha256:runsrc123")
        self.assertEqual(ev["schemaVersion"], "1.0")
        self.assertEqual(ev["artifact"]["application"]["sourceDigest"], "sha256:appsrc123")
        self.assertEqual(ev["artifact"]["runner"]["sourceDigest"], "sha256:runsrc123")
        self.assertTrue(ev["evidence"]["scanner_status"]["vulnerability_app"]["completed"])

    def test_opa_evaluation_and_predicate(self):
        ev = build_normalized_evidence("sha256:appsrc123", "sha256:runsrc123")
        with open("evidence.json", "w") as f:
            json.dump(ev, f)

        pred = evaluate_and_generate_decision("evidence.json", "promotion-decision.json")
        self.assertIn("opaDecision", pred)
        self.assertEqual(pred["opaDecision"]["status"], "MANUAL_REVIEW")

        # Validate with validate_promotion_decision.py
        self.assertTrue(validate_predicate(
            "promotion-decision.json",
            expected_app_promoted_digest="sha256:appsrc123",
            expected_runner_promoted_digest="sha256:runsrc123",
            expected_repository="llody9977/artifactgate"
        ))

if __name__ == "__main__":
    unittest.main()
