package artifactgate.licenses_test

import rego.v1
import data.artifactgate.licenses

test_prohibited_license_blocks if {
	test_inp := {
		"evidence": {
			"licenses": [{
				"component": "bad-lib",
				"license_id": "AGPL-3.0-only",
			}],
		},
	}
	res := licenses.block with input as test_inp
	count(res) == 1
}

test_allowed_license_passes if {
	test_inp := {
		"evidence": {
			"licenses": [{
				"component": "good-lib",
				"license_id": "MIT",
			}],
		},
	}
	res := licenses.block with input as test_inp
	count(res) == 0
}
