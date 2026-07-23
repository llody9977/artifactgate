package artifactgate.vulnerabilities_test

import rego.v1
import data.artifactgate.vulnerabilities

test_kev_vulnerability_blocks if {
	test_inp := {
		"evidence": {
			"vulnerabilities": [{
				"id": "CVE-2026-1001",
				"severity": "CRITICAL",
				"in_kev": true,
				"epss": 0.50,
				"age_days": 10,
				"vector": "AV:N/AC:L/PR:N",
			}],
		},
		"exceptions": [],
	}
	res := vulnerabilities.block with input as test_inp
	count(res) == 2 # 1 for KEV, 1 for CRITICAL
}

test_valid_waiver_bypasses_kev_block if {
	future_date := sprintf("%d-01-01T00:00:00Z", [time.date(time.now_ns())[0] + 1])
	test_inp := {
		"evidence": {
			"vulnerabilities": [{
				"id": "CVE-2026-1001",
				"severity": "CRITICAL",
				"in_kev": true,
				"epss": 0.50,
				"age_days": 10,
				"vector": "AV:N/AC:L/PR:N",
			}],
		},
		"exceptions": [{
			"exception_id": "W-1",
			"accepted_cves": ["CVE-2026-1001"],
			"expires_at": future_date,
			"approver": "security-team",
		}],
	}
	res := vulnerabilities.block with input as test_inp
	count(res) == 0
}
