package artifactgate.vulnerabilities

import rego.v1

block contains finding if {
	vuln := input.evidence.vulnerabilities[_]
	vuln.in_kev == true
	not valid_waiver(vuln.id)
	finding := {
		"rule_id": "VULN-001",
		"category": "vulnerability",
		"severity": "block",
		"subject": vuln.id,
		"message": sprintf("%s is listed in CISA KEV active exploitation catalog", [vuln.id]),
		"remediation": "Upgrade upstream image or submit active waiver with compensating controls",
	}
}

block contains finding if {
	vuln := input.evidence.vulnerabilities[_]
	vuln.severity == "CRITICAL"
	not valid_waiver(vuln.id)
	finding := {
		"rule_id": "VULN-002",
		"category": "vulnerability",
		"severity": "block",
		"subject": vuln.id,
		"message": sprintf("Critical vulnerability %s found in image layer", [vuln.id]),
		"remediation": "Remediate Critical vulnerability or submit active waiver",
	}
}

review contains finding if {
	vuln := input.evidence.vulnerabilities[_]
	vuln.severity == "HIGH"
	vuln.epss >= data.config.vulnerability_policy.epss_high_threshold
	not valid_waiver(vuln.id)
	finding := {
		"rule_id": "VULN-003",
		"category": "vulnerability",
		"severity": "review",
		"subject": vuln.id,
		"message": sprintf("High vulnerability %s exceeds EPSS threshold (EPSS: %.4f)", [vuln.id, vuln.epss]),
		"remediation": "Review EPSS risk or submit active waiver",
	}
}

review contains finding if {
	vuln := input.evidence.vulnerabilities[_]
	vuln.severity == "HIGH"
	vuln.age_days >= data.config.vulnerability_policy.max_age_days
	not valid_waiver(vuln.id)
	finding := {
		"rule_id": "VULN-004",
		"category": "vulnerability",
		"severity": "review",
		"subject": vuln.id,
		"message": sprintf("High vulnerability %s is older than max allowed age (%d days)", [vuln.id, vuln.age_days]),
		"remediation": "Review unpatched CVE age or submit active waiver",
	}
}

review contains finding if {
	vuln := input.evidence.vulnerabilities[_]
	vuln.vector == "AV:N/AC:L/PR:N"
	not valid_waiver(vuln.id)
	finding := {
		"rule_id": "VULN-005",
		"category": "vulnerability",
		"severity": "review",
		"subject": vuln.id,
		"message": sprintf("Pre-Auth Network Exploit vector (AV:N/AC:L/PR:N) detected on %s", [vuln.id]),
		"remediation": "Review unauthenticated network exposure vector",
	}
}

valid_waiver(cve) if {
	w := input.exceptions[_]
	cve in w.accepted_cves
	time.parse_rfc3339_ns(w.expires_at) > time.now_ns()
}
