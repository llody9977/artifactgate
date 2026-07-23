package artifactgate.decision_test

import rego.v1
import data.artifactgate.decision

test_approved_decision if {
	test_inp := {
		"artifact": {
			"application": {"source": "n8nio/n8n"},
			"runner": {"source": "n8nio/runners"},
			"platform": "linux/amd64",
		},
		"context": {
			"environment": "production",
			"workflowRunId": "123",
			"repository": "llody9977/artifactgate",
		},
		"evidence": {
			"vulnerabilities": [],
			"licenses": [],
			"secrets": [],
			"malware": [],
			"sbom": {"application_generated": true, "runner_generated": true},
			"runtime": {"app_status": "PASSED", "runner_status": "PASSED"},
			"scanner_status": {
				"vulnerability_app": {"completed": true},
				"vulnerability_runner": {"completed": true},
				"secret_app": {"completed": true},
				"secret_runner": {"completed": true},
				"malware_app": {"completed": true},
				"malware_runner": {"completed": true},
				"license_app": {"completed": true},
				"license_runner": {"completed": true},
				"sbom_app": {"completed": true},
				"sbom_runner": {"completed": true},
				"runtime_app": {"completed": true},
				"policy_hash": {"verified": true},
			},
		},
		"exceptions": [],
	}
	res := decision.decision with input as test_inp
	res.status == "APPROVED"
	res.blocking_findings == 0
	res.review_findings == 0
}

test_manual_review_decision_on_runner_exemption if {
	test_inp := {
		"artifact": {
			"application": {"source": "n8nio/n8n"},
			"runner": {"source": "n8nio/runners"},
			"platform": "linux/amd64",
		},
		"context": {
			"environment": "production",
			"workflowRunId": "123",
			"repository": "llody9977/artifactgate",
		},
		"evidence": {
			"vulnerabilities": [],
			"licenses": [],
			"secrets": [],
			"malware": [],
			"sbom": {"application_generated": true, "runner_generated": true},
			"runtime": {"app_status": "PASSED", "runner_status": "EXEMPTED"},
			"scanner_status": {
				"vulnerability_app": {"completed": true},
				"vulnerability_runner": {"completed": true},
				"secret_app": {"completed": true},
				"secret_runner": {"completed": true},
				"malware_app": {"completed": true},
				"malware_runner": {"completed": true},
				"license_app": {"completed": true},
				"license_runner": {"completed": true},
				"sbom_app": {"completed": true},
				"sbom_runner": {"completed": true},
				"runtime_app": {"completed": true},
				"policy_hash": {"verified": true},
			},
		},
		"exceptions": [],
	}
	res := decision.decision with input as test_inp
	res.status == "MANUAL_REVIEW"
	res.blocking_findings == 0
	res.review_findings == 1
}
