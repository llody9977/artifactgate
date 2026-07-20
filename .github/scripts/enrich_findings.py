#!/usr/bin/env python3
"""
Enrich Trivy findings with CISA KEV membership, EPSS scores, vulnerability age,
and the promotion gate decision used by the image promotion workflow.

Usage:
    python3 enrich_findings.py <trivy-report-in.json> <kev.json> <trivy-report-out.json>
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

EPSS_BATCH_SIZE = 100
CRITICAL_HIGH = {"CRITICAL", "HIGH"}
EPSS_RISK_THRESHOLDS = [
    (0.10, "CRITICAL"),
    (0.02, "HIGH"),
    (0.005, "MEDIUM"),
    (0.0, "LOW"),
]


def parse_date(raw: str):
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).astimezone(timezone.utc)
    except ValueError:
        return None


def fetch_epss_scores(cve_ids):
    scores = {}
    if not cve_ids:
        return scores

    fixture_path = os.environ.get("EPSS_DATA_FILE")
    if fixture_path:
        with open(fixture_path) as f:
            payload = json.load(f)
        for item in payload.get("data", []):
            cve = item.get("cve")
            try:
                score = float(item.get("epss", 0.0))
            except (TypeError, ValueError):
                score = 0.0
            if cve:
                scores[cve] = score
        return scores

    unique_ids = sorted(set(cve_ids))
    for index in range(0, len(unique_ids), EPSS_BATCH_SIZE):
        batch = unique_ids[index:index + EPSS_BATCH_SIZE]
        query = urllib.parse.urlencode({"cve": ",".join(batch)})
        url = f"https://api.first.org/data/v1/epss?{query}"
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                payload = json.load(response)
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Failed to fetch EPSS data: {exc}") from exc

        for item in payload.get("data", []):
            cve = item.get("cve")
            try:
                score = float(item.get("epss", 0.0))
            except (TypeError, ValueError):
                score = 0.0
            if cve:
                scores[cve] = score
    return scores


def epss_risk(score) -> str:
    if score is None:
        return "UNKNOWN"
    for threshold, label in EPSS_RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def main():
    if len(sys.argv) != 4:
        print("Usage: python3 enrich_findings.py <trivy-report-in.json> <kev.json> <trivy-report-out.json>")
        sys.exit(1)

    trivy_in, kev_path, trivy_out = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(trivy_in) as f:
        report = json.load(f)

    with open(kev_path) as f:
        kev_data = json.load(f)

    kev_ids = {item["cveID"] for item in kev_data.get("vulnerabilities", []) if item.get("cveID")}

    findings = []
    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(vuln)

    cve_ids = [vuln.get("VulnerabilityID") for vuln in findings if vuln.get("VulnerabilityID")]
    epss_scores = fetch_epss_scores(cve_ids)
    now = datetime.now(timezone.utc)

    summary = {
        "critical_high_count": 0,
        "manual_review_count": 0,
        "auto_allowed_critical_high_count": 0,
        "older_than_30_days_count": 0,
        "kev_critical_high_count": 0,
        "epss_high_or_critical_count": 0,
        "unknown_age_critical_high_count": 0,
    }

    for vuln in findings:
        cve_id = vuln.get("VulnerabilityID", "")
        severity = vuln.get("Severity", "UNKNOWN")
        published = parse_date(vuln.get("PublishedDate", ""))
        age_days = (now - published).days if published else None
        kev_hit = cve_id in kev_ids
        epss_score = epss_scores.get(cve_id)
        epss_label = epss_risk(epss_score)
        epss_percent = round(epss_score * 100, 2) if epss_score is not None else None
        reachable = vuln.get("RuntimeObserved")

        gate_decision = "AUTO_ALLOWED"
        gate_reasons = []

        if severity in CRITICAL_HIGH:
            summary["critical_high_count"] += 1

            if age_days is None:
                gate_decision = "MANUAL_REVIEW"
                gate_reasons.append("age_unknown")
                summary["unknown_age_critical_high_count"] += 1
            elif age_days >= 30:
                gate_decision = "MANUAL_REVIEW"
                gate_reasons.append("age_30d_or_more")
                summary["older_than_30_days_count"] += 1

            if kev_hit:
                gate_decision = "MANUAL_REVIEW"
                gate_reasons.append("kev_match")
                summary["kev_critical_high_count"] += 1

            if epss_label in {"HIGH", "CRITICAL"}:
                gate_decision = "MANUAL_REVIEW"
                gate_reasons.append(f"epss_{epss_label.lower()}")
                summary["epss_high_or_critical_count"] += 1

            if epss_label == "UNKNOWN":
                gate_decision = "MANUAL_REVIEW"
                gate_reasons.append("epss_unknown")

            if reachable is True:
                gate_decision = "MANUAL_REVIEW"
                gate_reasons.append("runtime_observed")

            if reachable is None:
                gate_decision = "MANUAL_REVIEW"
                gate_reasons.append("runtime_observation_unknown")

            if gate_decision == "MANUAL_REVIEW":
                summary["manual_review_count"] += 1
            else:
                summary["auto_allowed_critical_high_count"] += 1

        vuln["KevHit"] = kev_hit
        vuln["EpssScore"] = float(f"{epss_score:.6f}") if epss_score is not None else None
        vuln["EpssPercent"] = epss_percent
        vuln["EpssRisk"] = epss_label
        vuln["AgeDays"] = age_days
        vuln["GateDecision"] = gate_decision
        vuln["GateReasons"] = sorted(set(gate_reasons))

    # DAST / ZAP baseline check
    zap_report_path = os.environ.get("ZAP_REPORT_FILE")
    if zap_report_path:
        zap_manual_review = False
        zap_reasons = []

        # Read rules.tsv if exists
        zap_rules_path = ".zap/rules.tsv"
        ignored_alert_ids = set()
        if os.path.exists(zap_rules_path):
            try:
                with open(zap_rules_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split("\t")
                        if len(parts) >= 3 and parts[2].strip().upper() == "IGNORE":
                            ignored_alert_ids.add(parts[0].strip())
            except Exception as exc:
                print(f"Warning: Failed to load ZAP rules file: {exc}", file=sys.stderr)

        if not os.path.exists(zap_report_path):
            zap_manual_review = True
            zap_reasons.append("dast_report_missing")
        else:
            try:
                with open(zap_report_path) as f:
                    zap_data = json.load(f)
                high_alerts = 0
                for site in zap_data.get("site", []):
                    for alert in site.get("alerts", []):
                        alert_id = alert.get("pluginid")
                        risk_code = alert.get("riskcode")
                        if risk_code == "3":
                            if alert_id in ignored_alert_ids:
                                print(f"DAST Info: Ignoring ZAP alert {alert_id} ({alert.get('alert', '')}) per .zap/rules.tsv")
                                continue
                            high_alerts += 1
                if high_alerts > 0:
                    zap_manual_review = True
                    zap_reasons.append(f"dast_high_risk_alerts_{high_alerts}")
            except Exception as exc:
                zap_manual_review = True
                zap_reasons.append("dast_report_malformed")

        if zap_manual_review:
            summary["manual_review_count"] += 1
            summary["zap_reasons"] = zap_reasons

    summary["requires_manual_review"] = summary["manual_review_count"] > 0
    summary["auto_promotion_allowed"] = not summary["requires_manual_review"]
    report["AnalysisSummary"] = summary
    report["Metadata"] = report.get("Metadata", {})
    report["Metadata"]["epssThresholds"] = {
        "critical": 10.0,
        "high": 2.0,
        "medium": 0.5,
        "low": 0.0,
        "unit": "percent_probability_of_exploitation_within_30_days",
    }

    with open(trivy_out, "w") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    print(
        "Enriched findings:"
        f" {summary['critical_high_count']} critical/high,"
        f" {summary['manual_review_count']} require manual review,"
        f" {summary['auto_allowed_critical_high_count']} auto-eligible"
    )


if __name__ == "__main__":
    main()
