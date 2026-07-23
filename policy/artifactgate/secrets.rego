package artifactgate.secrets

import rego.v1

block contains finding if {
	secret := input.evidence.secrets[_]
	finding := {
		"rule_id": "SEC-001",
		"category": "secret",
		"severity": "block",
		"subject": secret.rule_id,
		"message": sprintf("Embedded secret detected in container layer: %s", [secret.rule_id]),
		"remediation": "Remove hardcoded credentials from container layers upstream",
	}
}
