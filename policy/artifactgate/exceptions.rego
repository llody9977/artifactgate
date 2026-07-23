package artifactgate.exceptions

import rego.v1

block contains finding if {
	exc := input.exceptions[_]
	time.parse_rfc3339_ns(exc.expires_at) <= time.now_ns()
	finding := {
		"rule_id": "EXC-001",
		"category": "exception",
		"severity": "block",
		"subject": exc.exception_id,
		"message": sprintf("Waiver exception '%s' has expired on %s", [exc.exception_id, exc.expires_at]),
		"remediation": "Re-triage vulnerability or submit updated unexpired waiver",
	}
}

block contains finding if {
	exc := input.exceptions[_]
	not exc.approver
	finding := {
		"rule_id": "EXC-002",
		"category": "exception",
		"severity": "block",
		"subject": exc.exception_id,
		"message": sprintf("Waiver exception '%s' is missing accountable reviewer approval", [exc.exception_id]),
		"remediation": "Obtain reviewer approval in trusted-promotion environment",
	}
}
