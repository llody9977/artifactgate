package artifactgate.decision

import rego.v1
import data.artifactgate.evidence
import data.artifactgate.exceptions
import data.artifactgate.licenses
import data.artifactgate.malware
import data.artifactgate.runtime
import data.artifactgate.secrets
import data.artifactgate.source
import data.artifactgate.vulnerabilities

blocking_set := source.block | evidence.block | secrets.block | malware.block | licenses.block | vulnerabilities.block | runtime.block | exceptions.block
review_set := licenses.review | vulnerabilities.review | runtime.review

blocking_findings := [x | x := blocking_set[_]]
review_findings := [x | x := review_set[_]]

all_findings := [x | x := (blocking_set | review_set)[_]]

has_active_waiver if {
	exc := input.exceptions[_]
	count(exc.accepted_cves) > 0
	time.parse_rfc3339_ns(exc.expires_at) > time.now_ns()
}

decision := result if {
	count(blocking_findings) > 0
	result := {
		"status": "REJECTED",
		"policy_version": "2026.07",
		"blocking_findings": count(blocking_findings),
		"review_findings": count(review_findings),
		"findings": all_findings,
	}
}

decision := result if {
	count(blocking_findings) == 0
	has_active_waiver
	result := {
		"status": "APPROVED_WITH_EXCEPTION",
		"policy_version": "2026.07",
		"blocking_findings": 0,
		"review_findings": count(review_findings),
		"findings": review_findings,
	}
}

decision := result if {
	count(blocking_findings) == 0
	not has_active_waiver
	count(review_findings) > 0
	result := {
		"status": "MANUAL_REVIEW",
		"policy_version": "2026.07",
		"blocking_findings": 0,
		"review_findings": count(review_findings),
		"findings": review_findings,
	}
}

decision := result if {
	count(blocking_findings) == 0
	not has_active_waiver
	count(review_findings) == 0
	result := {
		"status": "APPROVED",
		"policy_version": "2026.07",
		"blocking_findings": 0,
		"review_findings": 0,
		"findings": [],
	}
}
