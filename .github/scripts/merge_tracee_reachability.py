#!/usr/bin/env python3
"""
Merge Tracee runtime evidence into a Trivy report and annotate each finding
with a package-level reachability signal.

Usage:
    python3 merge_tracee_reachability.py <trivy-report-in.json> <package-files.tsv> <tracee-events.jsonl> <target-container-id|target-container-id-file> <trivy-report-out.json>
"""

import json
import sys

PATH_KEYS = {
    "pathname",
    "cmdpath",
    "path",
    "file_path",
    "library_path",
    "shared_object_path",
    "interpreter_pathname",
}


def normalize_path(raw):
    if not raw or not isinstance(raw, str):
        return None
    cleaned = raw.strip()
    if not cleaned.startswith("/"):
        return None
    return cleaned.split(" (deleted)", 1)[0]


def extract_container_ids(event):
    container_ids = set()
    direct_keys = ("containerId", "container_id")
    for key in direct_keys:
        value = event.get(key)
        if isinstance(value, str) and value:
            container_ids.add(value)

    for parent_key in ("container", "kubernetes"):
        parent = event.get(parent_key)
        if isinstance(parent, dict):
            for child_key in ("id", "containerId", "container_id"):
                value = parent.get(child_key)
                if isinstance(value, str) and value:
                    container_ids.add(value)
    return container_ids


def extract_event_name(event):
    for key in ("eventName", "event_name"):
        value = event.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def extract_arg_map(event):
    for key in ("eventArguments", "args", "arguments", "data"):
        value = event.get(key)
        if isinstance(value, dict):
            return value
        if isinstance(value, list):
            result = {}
            for item in value:
                if not isinstance(item, dict):
                    continue
                name = item.get("name") or item.get("argMeta", {}).get("name")
                arg_value = item.get("value")
                if isinstance(arg_value, dict) and "value" in arg_value:
                    arg_value = arg_value["value"]
                if name:
                    result[name] = arg_value
            return result
    return {}


def load_package_paths(path):
    package_paths = {}
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line or "\t" not in line:
                continue
            pkg, file_path = line.split("\t", 1)
            normalized = normalize_path(file_path)
            if not normalized:
                continue
            package_paths.setdefault(pkg, set()).add(normalized)
    return package_paths


def load_observed_paths(tracee_path, target_container_id):
    observed_paths = set()
    matched_events = 0
    target_prefix = target_container_id[:12]

    with open(tracee_path) as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            container_ids = extract_container_ids(event)
            if not container_ids:
                continue
            if not any(cid.startswith(target_prefix) or target_container_id.startswith(cid) for cid in container_ids):
                continue

            if extract_event_name(event) not in {"sched_process_exec", "shared_object_loaded", "security_file_open"}:
                continue

            args = extract_arg_map(event)
            for key, value in args.items():
                if key not in PATH_KEYS:
                    continue
                normalized = normalize_path(value)
                if normalized:
                    observed_paths.add(normalized)
                    matched_events += 1
    return observed_paths, matched_events


def main():
    if len(sys.argv) != 6:
        print(
            "Usage: python3 merge_tracee_reachability.py <trivy-report-in.json> <package-files.tsv> <tracee-events.jsonl> <target-container-id|target-container-id-file> <trivy-report-out.json>"
        )
        sys.exit(1)

    report_in, package_tsv, tracee_events, target_container_ref, report_out = sys.argv[1:]

    try:
        with open(target_container_ref) as f:
            target_container_id = f.read().strip()
    except OSError:
        target_container_id = target_container_ref.strip()

    if not target_container_id:
        print("Target container id is empty.")
        sys.exit(1)

    with open(report_in) as f:
        report = json.load(f)

    package_paths = load_package_paths(package_tsv)
    observed_paths, matched_events = load_observed_paths(tracee_events, target_container_id)

    observed_vulnerabilities_count = 0
    observed_packages = {pkg for pkg, files in package_paths.items() if files.intersection(observed_paths)}
    packages_observed_count = len(observed_packages)
    packages_total_count = len(package_paths)
    coverage_ratio = packages_observed_count / packages_total_count if packages_total_count > 0 else 0.0

    for result in report.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            package_name = vuln.get("PkgName", "")
            candidates = package_paths.get(package_name, set())
            evidence = sorted(path for path in candidates if path in observed_paths)
            
            # Default logic: True if loaded, False if not loaded (provided some events matched), None if no package files mapped
            observed = True if evidence else (False if candidates and matched_events > 0 else None)
            
            # Downgrade rule: if package-level runtime observation coverage is < 20%, downgrade False to None (Unknown)
            # because we cannot reliably assert 'Not observed' without a representative test run.
            if observed is False and coverage_ratio < 0.20:
                observed = None

            if observed is True:
                observed_vulnerabilities_count += 1
            vuln["RuntimeObserved"] = observed
            vuln["RuntimeObservation"] = (
                "Observed" if observed is True
                else "Not observed" if observed is False
                else "Unknown"
            )
            vuln["ReachabilityEvidence"] = evidence[:5]

    report["RuntimeObservationSummary"] = {
        "tracee_runtime_signal": "package_file_exec_or_load",
        "observed_paths_count": len(observed_paths),
        "matched_event_count": matched_events,
        "packages_observed_count": packages_observed_count,
        "packages_total_count": packages_total_count,
        "packages_coverage_pct": round(coverage_ratio * 100, 2),
        "observed_vulnerability_count": observed_vulnerabilities_count,
        "limitations": "A negative result means only that mapped package files were not observed during this smoke test; it does not prove code is unreachable.",
        "target_container_id": target_container_id[:12],
    }

    with open(report_out, "w") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    print(
        "Merged Tracee reachability:"
        f" {len(observed_paths)} observed paths,"
        f" {matched_events} matched events,"
        f" {observed_vulnerabilities_count} observed vulnerabilities"
    )


if __name__ == "__main__":
    main()
