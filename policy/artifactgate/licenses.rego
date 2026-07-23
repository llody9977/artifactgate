package artifactgate.licenses

import rego.v1

block contains finding if {
	component := input.evidence.licenses[_]
	component.license_id in data.config.license_policy.prohibited
	finding := {
		"rule_id": "LIC-001",
		"category": "license",
		"severity": "block",
		"subject": component.component,
		"message": sprintf("Component '%s' uses prohibited licence '%s'", [component.component, component.license_id]),
		"remediation": "Replace component or obtain legal exemption for prohibited copyleft licence",
	}
}

review contains finding if {
	component := input.evidence.licenses[_]
	component.license_id in data.config.license_policy.review_required
	finding := {
		"rule_id": "LIC-002",
		"category": "license",
		"severity": "review",
		"subject": component.component,
		"message": sprintf("Licence '%s' on component '%s' requires legal review", [component.license_id, component.component]),
		"remediation": "Submit licence terms to legal review for risk acceptance",
	}
}

review contains finding if {
	component := input.evidence.licenses[_]
	component.license_id == "UNKNOWN"
	finding := {
		"rule_id": "LIC-003",
		"category": "license",
		"severity": "review",
		"subject": component.component,
		"message": sprintf("Component '%s' has unclassified licence status", [component.component]),
		"remediation": "Identify component licence source and declare status",
	}
}
