package artifactgate.source

import rego.v1

block contains finding if {
	app_source := input.artifact.application.source
	not app_source in data.config.trusted_sources.allowed_sources
	finding := {
		"rule_id": "SRC-001",
		"category": "source",
		"severity": "block",
		"subject": app_source,
		"message": sprintf("Application source '%s' is not in allowed upstream sources list", [app_source]),
		"remediation": "Update policy/data/config.json or use an allowed source image",
	}
}

block contains finding if {
	runner_source := input.artifact.runner.source
	not runner_source in data.config.trusted_sources.allowed_sources
	finding := {
		"rule_id": "SRC-002",
		"category": "source",
		"severity": "block",
		"subject": runner_source,
		"message": sprintf("Runner source '%s' is not in allowed upstream sources list", [runner_source]),
		"remediation": "Update policy/data/config.json or use an allowed runner image",
	}
}

block contains finding if {
	platform := input.artifact.platform
	not platform in data.config.trusted_sources.allowed_platforms
	finding := {
		"rule_id": "SRC-003",
		"category": "source",
		"severity": "block",
		"subject": platform,
		"message": sprintf("Platform '%s' is not supported (allowed: linux/amd64)", [platform]),
		"remediation": "Promote only linux/amd64 workload images for byte-parity evaluation",
	}
}
