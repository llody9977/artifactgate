package artifactgate.runtime

import rego.v1

block contains finding if {
	app_st := input.evidence.runtime.app_status
	not app_st in {"PASSED", "COMPLETED"}
	finding := {
		"rule_id": "RNT-001",
		"category": "runtime",
		"severity": "block",
		"subject": "application_runtime",
		"message": sprintf("Application runtime eBPF observation status is '%s'", [app_st]),
		"remediation": "Verify application smoke test execution and eBPF tracing log",
	}
}

review contains finding if {
	run_st := input.evidence.runtime.runner_status
	run_st == "EXEMPTED"
	finding := {
		"rule_id": "RNT-002",
		"category": "runtime",
		"severity": "info",
		"subject": "runner_runtime_exemption",
		"message": "Task runner dynamic observation is explicitly exempted under policy rule runtime.runner.exemption",
		"remediation": "Assurance gap recorded in decision predicate",
	}
}
