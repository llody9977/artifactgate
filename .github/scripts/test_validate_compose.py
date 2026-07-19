#!/usr/bin/env python3
import copy
import json
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / ".github/scripts/validate_compose.py"

base_service = {
    "privileged": False,
    "read_only": True,
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true", "apparmor:docker-default"],
    "restart": "on-failure:5",
    "user": "1000:1000",
    "pids_limit": 200,
    "mem_limit": 1073741824,
    "cpus": 1.0,
    "volumes": [],
}
model = {"services": {"n8n": copy.deepcopy(base_service), "task-runners": copy.deepcopy(base_service)}}
model["services"]["n8n"].update({
    "image": "ghcr.io/llody9977/artifactgate/n8n-trusted@sha256:" + "a" * 64,
    "ports": [{"host_ip": "127.0.0.1", "published": "5678", "target": 5678}],
})
model["services"]["task-runners"]["image"] = "ghcr.io/llody9977/artifactgate/n8n-runners-trusted@sha256:" + "b" * 64


def run(payload):
    with tempfile.NamedTemporaryFile("w", suffix=".json") as handle:
        json.dump(payload, handle)
        handle.flush()
        return subprocess.run(["python3", str(VALIDATOR), handle.name], check=False, capture_output=True, text=True)


assert run(model).returncode == 0
broken = copy.deepcopy(model)
broken["services"]["task-runners"]["read_only"] = False
result = run(broken)
assert result.returncode == 1 and "task-runners: root filesystem" in result.stderr
print("Compose hardening validator fixtures passed.")
