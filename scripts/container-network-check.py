#!/usr/bin/env python3
"""Actual Docker namespace isolation checks, using only synthetic local traffic.

Run after CI Compose readiness with COMPOSE_PROJECT_NAME=fuse-ci-<run>-<attempt>.
Uses the already-built agent image by immutable ID; never pulls or builds. All
fixture/probe containers use a fresh internal network or join an existing app
network namespace without changing the app's network membership. No host
firewall, capabilities, credentials, mounts, provider calls or public targets.

This proves observed IPv4 TCP service segmentation/off-network fixture denial
and absence of active IPv4/IPv6 default routes on this Docker host. It does NOT
certify LIVE/public Internet filtering, metadata/host-gateway denial, or IPv6
socket isolation. Those remain explicitly NOT_RUN in the safe summary.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PROBE = Path(__file__).with_name("container_network_probe.py").read_text(encoding="utf-8")
SUMMARY = ROOT / "safe-artifacts/container-network-summary.json"
SERVICES = {"agent": {"kyc"}, "backend": {"web", "data", "kyc"},
            "frontend": {"web"}, "postgres": {"data"}}
PORTS = {"agent": 8001, "backend": 8080, "frontend": 8080, "postgres": 5432}
PAIRS = {"agent": {"backend": "ALLOW", "postgres": "DENY", "frontend": "DENY"},
         "frontend": {"backend": "ALLOW", "postgres": "DENY", "agent": "DENY"},
         "backend": {"agent": "ALLOW", "postgres": "ALLOW", "frontend": "ALLOW"},
         "postgres": {"backend": "ALLOW"}}
FIXTURE_PORT = 18089
FIXTURE_SERVER = """import socket
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',18089));s.listen(16)
while True:
 c,_=s.accept()
 with c:
  c.settimeout(2)
  try:c.sendall(b'FUSE_SYNTHETIC_NETWORK_FIXTURE\\n')
  except OSError:pass
"""
INSPECT = ('{"id":{{json .Id}},"image":{{json .Image}},"state":{{json .State.Status}},'
           '"networks":{{json .NetworkSettings.Networks}}}')


class VerificationError(RuntimeError):
    """Only fixed, non-sensitive reason codes may reach the public report."""


def docker(*args, timeout=35):
    result = subprocess.run(["docker", *args], cwd=ROOT, text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise VerificationError("DOCKER_COMMAND_FAILED")
    return result.stdout.strip()


def valid_id(value):
    if not re.fullmatch(r"[a-f0-9]{12,64}", value):
        raise VerificationError("INVALID_DOCKER_RESOURCE_ID")
    return value


def inspect_container(container):
    return json.loads(docker("inspect", "--format", INSPECT, container))


def inspect_services(project):
    result = {}
    for service, expected_networks in SERVICES.items():
        ids = docker("ps", "--filter", f"label=com.docker.compose.project={project}",
                     "--filter", f"label=com.docker.compose.service={service}",
                     "--format", "{{.ID}}").splitlines()
        if len(ids) != 1:
            raise VerificationError("EXPECTED_ONE_RUNNING_CONTAINER_PER_SERVICE")
        observed = inspect_container(valid_id(ids[0]))
        if observed["state"] != "running" or set(observed["networks"]) != {
                f"{project}_{network}" for network in expected_networks}:
            raise VerificationError("APP_NETWORK_MEMBERSHIP_CHANGED")
        for network in observed["networks"].values():
            meta = json.loads(docker("network", "inspect", "--format",
                '{"internal":{{json .Internal}},"driver":{{json .Driver}},'
                '"project":{{json (index .Labels "com.docker.compose.project")}}}',
                valid_id(network["NetworkID"])))
            if meta != {"internal": True, "driver": "bridge", "project": project}:
                raise VerificationError("APP_NETWORK_IS_NOT_ISOLATED_CI_BRIDGE")
        result[service] = observed
    image = result["agent"]["image"]
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise VerificationError("MISSING_IMMUTABLE_PROBE_IMAGE")
    # Check mode within the adapter without retrieving or printing its environment.
    docker("exec", result["agent"]["id"], "python", "-c",
           'import os; assert os.environ.get("FUSE_KYC_MODE")=="replay"; '
           'assert not os.environ.get("FUSE_LLM_API_KEY"); '
           'assert not os.environ.get("FUSE_LLM_MODEL")')
    return result


def address_on(container, network):
    address = container["networks"][network]["IPAddress"]
    ip = ipaddress.ip_address(address)
    if (ip.version != 4 or not ip.is_private or ip.is_loopback
            or ip.is_link_local or ip.is_unspecified or ip.is_multicast):
        raise VerificationError("UNEXPECTED_DOCKER_FIXTURE_ADDRESS")
    return str(ip)


def targets_for(service, containers, fixture_address):
    targets = []
    own_networks = set(containers[service]["networks"])
    for peer, expected in PAIRS[service].items():
        peer_networks = set(containers[peer]["networks"])
        candidates = own_networks & peer_networks if expected == "ALLOW" else peer_networks
        if not candidates:
            raise VerificationError("MISSING_EXPECTED_PEER_NETWORK")
        targets.append({"check": f"{service}_to_{peer}", "expected": expected,
                        "address": address_on(containers[peer], sorted(candidates)[0]),
                        "port": PORTS[peer]})
    targets.append({"check": f"{service}_to_off_network_fixture", "expected": "DENY",
                    "address": fixture_address, "port": FIXTURE_PORT})
    return targets


def validate_observation(result, targets, *, expect_no_default=True):
    if set(result) != {"checks", "ipv4DefaultRoutes", "ipv6DefaultRoutes"}:
        raise VerificationError("MALFORMED_PROBE_RESULT")
    checks = result["checks"]
    if len(checks) != len(targets):
        raise VerificationError("MISSING_PROBE_RESULT")
    for row, target in zip(checks, targets):
        if (set(row) != {"check", "expected", "observed", "status"}
                or row["check"] != target["check"] or row["expected"] != target["expected"]
                or row["status"] not in {"PASS", "FAIL"}
                or row["observed"] not in {"CONNECTED", "DENIED"}):
            raise VerificationError("MALFORMED_PROBE_RESULT")
        expected_observation = "CONNECTED" if target["expected"] == "ALLOW" else "DENIED"
        if row["status"] != "PASS" or row["observed"] != expected_observation:
            raise VerificationError("TCP_BOUNDARY_CHECK_FAILED")
    for key in ("ipv4DefaultRoutes", "ipv6DefaultRoutes"):
        if type(result[key]) is not int or result[key] < 0:
            raise VerificationError("MALFORMED_PROBE_RESULT")
        if expect_no_default and result[key] != 0:
            raise VerificationError("UNEXPECTED_EXTERNAL_DEFAULT_ROUTE")


class IsolatedRun:
    def __init__(self, image):
        self.image = image
        self.prefix = "fuse-net-check-" + uuid.uuid4().hex
        self.label = "com.finsec-fuse.network-check=" + self.prefix
        self.network = None
        self.containers = []

    def create_network(self):
        self.network = docker("network", "create", "--internal", "--driver", "bridge",
                              "--label", self.label, self.prefix)
        return valid_id(self.network)

    def run(self, suffix, network, script, arguments=(), *, detached=False):
        name = self.prefix + "-" + suffix
        self.containers.append(name)
        flags = ["--detach"] if detached else ["--rm"]
        return docker("run", *flags, "--pull=never", "--name", name, "--label", self.label,
                      "--network", network, "--user", "10001:10001", "--cap-drop", "ALL",
                      "--security-opt", "no-new-privileges:true", "--read-only",
                      "--pids-limit", "32", "--memory", "64m", "--cpus", "0.5",
                      "--entrypoint", "python", self.image, "-c", script, *arguments)

    def probe(self, suffix, network, targets):
        return json.loads(self.run(suffix, network, PROBE, (json.dumps(targets),)))

    def cleanup(self):
        # Never prune Docker, remove app containers, touch volumes, or tear down
        # another run. Names are unique and everything also has this run's label.
        for name in reversed(self.containers):
            try:
                subprocess.run(["docker", "rm", "--force", name], cwd=ROOT,
                               capture_output=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                pass  # Continue cleanup, then independently verify every resource.
        # Use the unique known name if create timed out after Docker created it.
        try:
            subprocess.run(["docker", "network", "rm", self.network or self.prefix], cwd=ROOT,
                           capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            pass
        remaining = docker("ps", "--all", "--filter", f"label={self.label}", "--quiet")
        networks = docker("network", "ls", "--filter", f"label={self.label}", "--quiet")
        return not remaining and not networks


def fresh_summary():
    return {"status": "NOT_RUN", "source": "REAL_DOCKER_SERVICE_NETWORK_NAMESPACES",
            "scope": "IPV4_TCP_SEGMENTATION_OFF_NETWORK_FIXTURE_AND_DEFAULT_ROUTE_ABSENCE",
            "providerCalls": False, "publicInternetConnections": False,
            "liveEgressPolicy": "NOT_RUN", "metadataAndHostGateway": "NOT_RUN",
            "ipv6SocketIsolation": "NOT_RUN", "cleanupVerified": False,
            "applicationNetworksUnchanged": False, "services": {}, "positiveControls": []}


def execute(summary):
    project = os.environ.get("COMPOSE_PROJECT_NAME", "")
    if not re.fullmatch(r"fuse-ci-[0-9]+-[0-9]+", project):
        raise VerificationError("ISOLATED_CI_PROJECT_REQUIRED")
    if not shutil.which("docker"):
        raise VerificationError("DOCKER_UNAVAILABLE")
    containers = inspect_services(project)
    work = IsolatedRun(containers["agent"]["image"])
    try:
        network = work.create_network()
        fixture_id = valid_id(work.run("fixture", network, FIXTURE_SERVER, detached=True))
        fixture = inspect_container(fixture_id)
        if set(fixture["networks"]) != {work.prefix}:
            raise VerificationError("FIXTURE_NETWORK_MEMBERSHIP_CHANGED")
        fixture_address = address_on(fixture, work.prefix)
        controls = [{"check": "off_network_fixture_positive_control", "expected": "ALLOW",
                     "address": fixture_address, "port": FIXTURE_PORT, "marker": True}]
        # Retry only synthetic fixture startup. An unavailable destination cannot
        # be mistaken for a successful network-denial result.
        for attempt in range(10):
            control = work.probe(f"control-start-{attempt}", network, controls)
            if all(row["status"] == "PASS" for row in control["checks"]):
                break
            time.sleep(0.2)
        validate_observation(control, controls)
        summary["positiveControls"].append("FIXTURE_REACHABLE_BEFORE_DENIAL_PROBES")
        for service in SERVICES:
            targets = targets_for(service, containers, fixture_address)
            result = work.probe(service, "container:" + containers[service]["id"], targets)
            validate_observation(result, targets)
            summary["services"][service] = result
        control = work.probe("control-end", network, controls)
        validate_observation(control, controls)
        summary["positiveControls"].append("FIXTURE_REACHABLE_AFTER_DENIAL_PROBES")
        if inspect_services(project) != containers:
            raise VerificationError("APPLICATION_CHANGED_DURING_TEST")
        summary["applicationNetworksUnchanged"] = True
        summary["status"] = "PASS"
    finally:
        summary["cleanupVerified"] = work.cleanup()
        if not summary["cleanupVerified"]:
            raise VerificationError("FIXTURE_CLEANUP_NOT_VERIFIED")


def emit(summary, path=SUMMARY):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise VerificationError("UNSAFE_SUMMARY_PATH")
    path.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    path.chmod(0o600)


def main():
    summary = fresh_summary()
    try:
        execute(summary)
    except VerificationError as error:
        summary["status"] = "NOT_RUN" if str(error) in {
            "DOCKER_UNAVAILABLE", "ISOLATED_CI_PROJECT_REQUIRED"} else "FAIL"
        summary["reason"] = str(error)
    except Exception:
        # Raw Docker errors and container output stay private.
        summary.update(status="FAIL", reason="CONTAINER_BOUNDARY_EXECUTION_FAILED")
    emit(summary)
    print("Container network boundary checks: " + summary["status"] +
          ". Scope: synthetic IPv4 fixtures and default routes; LIVE/public filtering NOT_RUN.")
    return int(summary["status"] != "PASS")


if __name__ == "__main__":
    raise SystemExit(main())
