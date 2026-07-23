package artifactgate.source_test

import rego.v1
import data.artifactgate.source

test_allowed_source if {
	test_inp := {
		"artifact": {
			"application": {"source": "n8nio/n8n"},
			"runner": {"source": "n8nio/runners"},
			"platform": "linux/amd64",
		},
	}
	res := source.block with input as test_inp
	count(res) == 0
}

test_disallowed_source if {
	test_inp := {
		"artifact": {
			"application": {"source": "untrusted/app"},
			"runner": {"source": "n8nio/runners"},
			"platform": "linux/amd64",
		},
	}
	res := source.block with input as test_inp
	count(res) == 1
}
