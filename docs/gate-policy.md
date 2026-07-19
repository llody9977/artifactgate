# Approval Gate Policy

## Why This Gate Exists

A CVE record tells you a vulnerability exists. It does not fully answer:

- whether it is being exploited in the wild
- how likely exploitation is in the near term
- whether the code path is materially exercised by the workload
- whether the finding is old enough to justify stricter handling

This repository uses a richer gate so promotion decisions are not based on severity alone.

## Enrichment Signals

### CISA KEV

`KEV` is the strongest urgency signal in this repository. If a `CRITICAL` or `HIGH` finding is already known exploited in the wild, it should not quietly auto-promote.

### EPSS

`EPSS` adds probability context for exploitation over the next 30 days. This helps distinguish likely-to-be-exploited findings from lower-signal severity-only noise.

### CVE Age

Age adds a tolerance-window signal. A fresh issue and a long-standing unresolved issue should not always be treated the same way.

### Runtime Observation

Tracee contributes bounded runtime context by showing whether mapped package files were observed loading during a container smoke run. “Not observed” does not prove that vulnerable code is unreachable.

Our runtime observation policy enforces three key principles:
1. **Observed Escalation**: If a package containing a `CRITICAL` or `HIGH` vulnerability is observed loading during the smoke run (`Observed`), the finding is escalated to `Manual review` with the reason `runtime_observed`.
2. **Coverage Downgrade**: The smoke test must exercise at least 20% of all mapped packages. If package-level coverage falls below 20%, all `Not observed` findings are downgraded to `Unknown`, forcing them to fail closed (requiring manual review).
3. **No De-escalation**: A vulnerability that is already flagged for manual review (due to age, KEV, or EPSS) is never downgraded to auto-allowed because it was not observed loading.

## Gate Policy

For `CRITICAL` and `HIGH` findings:

| Finding severity | KEV | EPSS | Age | Runtime Observation | Action |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `CRITICAL` / `HIGH` | Yes | Any | Any | Any | Manual review |
| `CRITICAL` / `HIGH` | No | Above repo threshold | Any | Any | Manual review |
| `CRITICAL` / `HIGH` | No | Below repo threshold | At least 30 days | Any | Manual review |
| `CRITICAL` / `HIGH` | No | Unknown | Any | Any | Manual review |
| `CRITICAL` / `HIGH` | No | Low | Unknown | Any | Manual review |
| `CRITICAL` / `HIGH` | No | Low | Any | Observed | Manual review |
| `CRITICAL` / `HIGH` | No | Low | Any | Unknown | Manual review |
| `CRITICAL` / `HIGH` | No | Below threshold | Under 30 days | Not Observed (Coverage &ge; 20%) | Auto-allowed |
| `MEDIUM` / `LOW` / `UNKNOWN` | No | Any | Any | Any | Reported, but does not directly trigger manual approval |

Unknown evidence is not converted to a zero score or a negative observation claim. Critical/high findings require manual review whenever age, EPSS or required runtime evidence is unavailable or coverage is insufficient.

## EPSS Policy Bands

These are repository policy bands, not official EPSS categories.

| EPSS score | Repository band | Meaning | Action |
| :--- | :--- | :--- | :--- |
| `< 0.5%` | Low | Exploitation currently looks unlikely at scale | Does not block auto-promotion by itself |
| `0.5% to < 2.0%` | Medium | Elevated likelihood, but below manual-review threshold | May still auto-promote if other checks are clear |
| `2.0% to < 10.0%` | High | Above this repository's manual-review threshold | Manual review for `CRITICAL` and `HIGH` findings |
| `>= 10.0%` | Critical | Very high predicted exploitation likelihood | Treat as urgent; manual review for `CRITICAL` and `HIGH` findings |

## Additional Hard Gates

These controls are not part of the CVE enrichment logic. They are direct blocking checks.

- `Licence findings`: Trivy reports licence findings for review; the repository does not claim that scanner severity alone establishes legal compatibility
- `Malware`: ClamAV blocks promotion if malware is detected
- `Secrets`: Trivy secret scanning blocks promotion
- `Policy violations`: disallowed source image or non-semver intake is rejected before promotion

## Day-2 Re-Scan Behavior

The latest promoted release is re-scanned on a schedule. If the current gate logic would now require manual review, the workflow opens an issue so the promoted artifact can be re-triaged.

Suggested operating model:

1. identify whether the trigger is KEV, EPSS, CVE age, or a combination
2. evaluate whether a newer upstream version is acceptable
3. document accepted CVEs, justification, compensating controls and a future expiry in the workflow waiver fields
4. revise deployment plans if the promoted image should be replaced quickly
