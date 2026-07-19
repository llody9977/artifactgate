#!/usr/bin/env bash
set -euo pipefail

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cat > "$tmpdir/trivy-report.raw.json" <<'EOF'
{
  "Results": [
    {
      "Target": "pkg",
      "Class": "os-pkgs",
      "Type": "alpine",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-1111",
          "PkgName": "busybox",
          "InstalledVersion": "1.0",
          "Severity": "HIGH",
          "PublishedDate": "2026-02-20T00:00:00Z"
        },
        {
          "VulnerabilityID": "CVE-2024-2222",
          "PkgName": "openssl",
          "InstalledVersion": "3.0",
          "Severity": "MEDIUM",
          "PublishedDate": "2025-12-01T00:00:00Z"
        },
        {
          "VulnerabilityID": "CVE-2024-3333",
          "PkgName": "zlib",
          "InstalledVersion": "1.3.1-r2",
          "Severity": "HIGH"
        }
      ]
    }
  ]
}
EOF

cat > "$tmpdir/package-files.tsv" <<'EOF'
busybox	/bin/busybox
openssl	/lib/libssl.so.3
zlib	/lib/libz.so.1
EOF

cat > "$tmpdir/tracee-events.jsonl" <<'EOF'
{"container":{"id":"host-no-match"},"eventName":"sched_process_exec","args":[{"name":"pathname","value":"/bin/busybox"}]}
{"container":{"id":"abc123deadbeef"},"eventName":"sched_process_exec","args":[{"name":"pathname","value":"/bin/busybox"}]}
EOF

printf 'abc123deadbeefcafebabe\n' > "$tmpdir/target-container-id.txt"
cat > "$tmpdir/kev.json" <<'EOF'
{"vulnerabilities":[]}
EOF

cat > "$tmpdir/epss.json" <<'EOF'
{
  "data": [
    {"cve": "CVE-2024-1111", "epss": "0.001"},
    {"cve": "CVE-2024-2222", "epss": "0.001"},
    {"cve": "CVE-2024-3333", "epss": "0.001"}
  ]
}
EOF

python3 .github/scripts/merge_tracee_reachability.py \
  "$tmpdir/trivy-report.raw.json" \
  "$tmpdir/package-files.tsv" \
  "$tmpdir/tracee-events.jsonl" \
  "$tmpdir/target-container-id.txt" \
  "$tmpdir/trivy-report.tracee.json"

EPSS_DATA_FILE="$tmpdir/epss.json" python3 .github/scripts/enrich_findings.py \
  "$tmpdir/trivy-report.tracee.json" \
  "$tmpdir/kev.json" \
  "$tmpdir/trivy-report.enriched.json"

summary_path="$tmpdir/summary.md"
GITHUB_STEP_SUMMARY="$summary_path" python3 .github/scripts/generate_summary.py \
  "$tmpdir/trivy-report.enriched.json" \
  "$tmpdir/kev.json" \
  "fixture"

jq -e '.RuntimeObservationSummary.matched_event_count == 1' "$tmpdir/trivy-report.tracee.json" > /dev/null
jq -e '.RuntimeObservationSummary.observed_vulnerability_count == 1' "$tmpdir/trivy-report.tracee.json" > /dev/null
jq -e '[.Results[]?.Vulnerabilities[]? | select(.VulnerabilityID == "CVE-2024-1111") | .RuntimeObservation] | any(. == "Observed")' "$tmpdir/trivy-report.enriched.json" > /dev/null
jq -e '[.Results[]?.Vulnerabilities[]? | select(.VulnerabilityID == "CVE-2024-2222") | .RuntimeObservation] | any(. == "Not observed")' "$tmpdir/trivy-report.enriched.json" > /dev/null
jq -e '[.Results[]?.Vulnerabilities[]? | select(.VulnerabilityID == "CVE-2024-3333") | .GateDecision] | any(. == "MANUAL_REVIEW")' "$tmpdir/trivy-report.enriched.json" > /dev/null
jq -e '.AnalysisSummary.unknown_age_critical_high_count == 1' "$tmpdir/trivy-report.enriched.json" > /dev/null
grep -q "Runtime Obs." "$summary_path"

python3 .github/scripts/generate_vex.py "$tmpdir/trivy-report.enriched.json" > "$tmpdir/vex.json"
jq -e '[.statements[] | select(.vulnerability.name == "CVE-2024-2222") | .status] | any(. == "under_investigation")' "$tmpdir/vex.json" >/dev/null
jq -e '[.statements[].status] | all(. != "not_affected")' "$tmpdir/vex.json" >/dev/null

echo "Tracee merge fixture passed."
