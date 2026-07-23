package artifactgate.evidence

import rego.v1

required_scanners := {
	"vulnerability_app",
	"vulnerability_runner",
	"secret_app",
	"secret_runner",
	"malware_app",
	"malware_runner",
	"license_app",
	"license_runner",
	"sbom_app",
	"sbom_runner",
	"runtime_app",
}

block contains finding if {
	scanner := required_scanners[_]
	is_completed(scanner) == false
	finding := {
		"rule_id": "EVID-001",
		"category": "evidence",
		"severity": "block",
		"subject": scanner,
		"message": sprintf("Required evidence item '%s' is missing or unverified", [scanner]),
		"remediation": "Re-run promotion pipeline to generate complete evidence set",
	}
}

is_completed(scanner) if {
	input.evidence.scanner_status[scanner].completed == true
} else = false

block contains finding if {
	is_policy_verified == false
	finding := {
		"rule_id": "EVID-002",
		"category": "evidence",
		"severity": "block",
		"subject": "policy_hash",
		"message": "Predicate policy hashes do not match local policy definitions",
		"remediation": "Re-generate decision predicate using current policy hashes",
	}
}

is_policy_verified if {
	input.evidence.scanner_status.policy_hash.verified == true
} else = false
