#!/usr/bin/env python3
"""Validate the rendered Compose model, service by service."""

import json
import sys


def fail(message, failures):
    failures.append(message)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate_compose.py <docker-compose-config.json>")
    with open(sys.argv[1], encoding="utf-8") as handle:
        model = json.load(handle)

    failures = []
    services = model.get("services", {})
    for name in ("n8n", "task-runners"):
        service = services.get(name)
        if not service:
            fail(f"{name}: service is missing", failures)
            continue
        if service.get("privileged"):
            fail(f"{name}: privileged mode is enabled", failures)
        if service.get("read_only") is not True:
            fail(f"{name}: root filesystem is not read-only", failures)
        if set(service.get("cap_drop", [])) != {"ALL"}:
            fail(f"{name}: cap_drop must contain only ALL", failures)
        security = set(service.get("security_opt", []))
        if "no-new-privileges:true" not in security:
            fail(f"{name}: no-new-privileges is missing", failures)
        if "apparmor:docker-default" not in security:
            fail(f"{name}: docker-default AppArmor profile is missing", failures)
        if any(item == "seccomp:unconfined" for item in security):
            fail(f"{name}: seccomp is disabled", failures)
        if service.get("restart") != "on-failure:5":
            fail(f"{name}: restart policy must be on-failure:5", failures)
        if str(service.get("user", "")).strip() in {"", "0", "root", "0:0"}:
            fail(f"{name}: an explicit non-root user is required", failures)
        if not service.get("pids_limit") or not service.get("mem_limit") or not service.get("cpus"):
            fail(f"{name}: CPU, memory, or PID limit is missing", failures)
        for mount in service.get("volumes", []):
            source = str(mount.get("source", "")) if isinstance(mount, dict) else str(mount)
            if source.startswith(("/etc", "/proc", "/sys", "/dev", "/run")) or "docker.sock" in source:
                fail(f"{name}: sensitive mount {source}", failures)

    n8n = services.get("n8n", {})
    published = n8n.get("ports", [])
    if not published or any(str(port.get("host_ip", "")) in {"", "0.0.0.0"} for port in published if isinstance(port, dict)):
        fail("n8n: published port must bind to a specific host interface", failures)

    for name, expected in {
        "n8n": "ghcr.io/llody9977/artifactgate/n8n-trusted@sha256:",
        "task-runners": "ghcr.io/llody9977/artifactgate/n8n-runners-trusted@sha256:",
    }.items():
        if not str(services.get(name, {}).get("image", "")).startswith(expected):
            fail(f"{name}: rendered image is not the expected trusted digest-pinned GHCR image", failures)

    if failures:
        print("\n".join(f"FAIL: {item}" for item in failures), file=sys.stderr)
        raise SystemExit(1)
    print("Rendered Compose model satisfies the project hardening profile for both services.")


if __name__ == "__main__":
    main()
