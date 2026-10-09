#!/usr/bin/env python3
"""Static Compose regression checks. These are NOT Docker/network execution proof.

Requires PyYAML from scripts/security/requirements.lock. No .env, secrets, private
assets, containers, provider endpoints, or external networks are read or used.
"""
from __future__ import annotations

import copy
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_NETWORKS = {
    "postgres": {"data"}, "agent": {"kyc"},
    "backend": {"web", "data", "kyc"}, "frontend": {"web"},
}
BACKEND_USER = "${FUSE_RUNTIME_UID:?Run scripts/bootstrap-dev.sh}:${FUSE_RUNTIME_GID:?Run scripts/bootstrap-dev.sh}"


class UniqueSafeLoader(yaml.SafeLoader):
    """Reject ambiguous duplicate source keys before resolving YAML merges."""
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key, _ in node.value:
            if key.tag == "tag:yaml.org,2002:merge":
                continue
            value = self.construct_object(key, deep=deep)
            if not isinstance(value, str) or value in keys:
                raise ValueError("Compose mapping has a duplicate or non-string key")
            keys.add(value)
        return super().construct_mapping(node, deep=deep)


def load_text(text):
    loader = UniqueSafeLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def load(name):
    return load_text((ROOT / name).read_text(encoding="utf-8"))


def base_violations(config):
    failures = []
    networks = config.get("networks", {})
    if set(networks) != {"web", "data", "kyc"}:
        failures.append("network set")
    for network in networks.values():
        if network.get("internal") is not True or network.get("driver") != "bridge" or network.get("external"):
            failures.append("external routing")
    services = config.get("services", {})
    if set(services) != set(EXPECTED_NETWORKS):
        failures.append("service set")
    for name, service in services.items():
        if set(service.get("networks", [])) != EXPECTED_NETWORKS.get(name):
            failures.append("network membership")
        if any(service.get(key) for key in ("network_mode", "privileged", "cap_add", "devices", "links",
                                          "external_links", "extra_hosts", "env_file", "pid", "ipc")):
            failures.append("privileged or implicit boundary")
        if service.get("cap_drop") != ["ALL"] or service.get("security_opt") != ["no-new-privileges:true"]:
            failures.append("capability boundary")
        if service.get("read_only") is not True:
            failures.append("writable root")
        if not isinstance(service.get("pids_limit"), int) or not 1 <= service["pids_limit"] <= 512:
            failures.append("process limit")
        expected_user = {"postgres": "postgres", "agent": "10001:10001", "backend": BACKEND_USER, "frontend": "101:101"}
        if service.get("user") != expected_user.get(name):
            failures.append("runtime identity")
        expected_ports = {"backend": ["127.0.0.1:8080:8080"], "frontend": ["127.0.0.1:5173:8080"]}
        if service.get("ports", []) != expected_ports.get(name, []):
            failures.append("host exposure")
    return failures


class ComposeSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = load("compose.yaml")
        cls.dev = load("compose.dev.yaml")
        cls.live = load("compose.live.yaml")
        cls.private = load("compose.private.yaml")

    def test_default_topology_and_hardening_contract(self):
        self.assertEqual([], base_violations(self.base))

    def test_only_required_service_pairs_share_a_network(self):
        memberships = {name: set(svc["networks"]) for name, svc in self.base["services"].items()}
        for a, b in (("frontend", "backend"), ("backend", "postgres"), ("backend", "agent")):
            self.assertTrue(memberships[a] & memberships[b], (a, b))
        for a, b in (("frontend", "postgres"), ("frontend", "agent"), ("agent", "postgres")):
            self.assertFalse(memberships[a] & memberships[b], (a, b))

    def test_base_replay_cannot_inherit_live_settings(self):
        for name in ("agent", "backend"):
            self.assertEqual("replay", self.base["services"][name]["environment"]["FUSE_KYC_MODE"])
        self.assertEqual("false", self.base["services"]["backend"]["environment"]["FUSE_EXPERIMENT_LIVE_ENABLED"])
        env = self.base["services"]["agent"]["environment"]
        self.assertEqual("", env["FUSE_LLM_API_KEY"])
        self.assertEqual("", env["FUSE_LLM_MODEL"])

    def test_adapter_never_receives_database_staff_or_signing_credentials(self):
        svc = self.base["services"]["agent"]
        self.assertEqual({"FUSE_SERVICE_TOKEN", "FUSE_KYC_MODE", "FUSE_LLM_API_KEY", "FUSE_LLM_MODEL", "PYTHONDONTWRITEBYTECODE"}, set(svc["environment"]))
        self.assertNotIn("secrets", svc)
        self.assertNotIn("volumes", svc)

    def test_provider_credentials_not_passed_to_other_services(self):
        for name in ("backend", "postgres", "frontend"):
            self.assertNotIn("FUSE_LLM_API_KEY", self.base["services"][name].get("environment", {}))
        self.assertFalse(any("PROXY" in key for svc in self.base["services"].values() for key in svc.get("environment", {})))

    def test_signing_key_is_java_only_and_not_repermissioned_in_compose(self):
        self.assertEqual({"fuse_signing_key": {"file": "./.secrets/signing.key"}}, self.base["secrets"])
        for name, svc in self.base["services"].items():
            self.assertEqual(["fuse_signing_key"] if name == "backend" else [], svc.get("secrets", []))
        self.assertEqual("/run/secrets/fuse_signing_key", self.base["services"]["backend"]["environment"]["FUSE_SIGNING_KEY_PATH"])
        self.assertEqual("${FUSE_SIGNING_KEY_ID:-local-v1}", self.base["services"]["backend"]["environment"]["FUSE_SIGNING_KEY_ID"])

    def test_fixed_backend_routes_preserve_database_and_adapter_access(self):
        env = self.base["services"]["backend"]["environment"]
        self.assertEqual("http://agent:8001", env["FUSE_KYC_BASE_URL"])
        self.assertEqual("jdbc:postgresql://postgres:5432/fuse", env["FUSE_DB_URL"])
        self.assertEqual("jdbc:postgresql://postgres:5432/fuse_experiments", env["FUSE_EXPERIMENT_DB_URL"])
        self.assertIn("proxy_pass http://backend:8080;", (ROOT / "frontend/nginx.conf").read_text())

    def test_writable_mounts_are_explicit_bounded_tmpfs_or_database(self):
        expected_tmp = {name: {"/tmp"} for name in self.base["services"]}
        expected_tmp["postgres"].add("/var/run/postgresql")
        for name, svc in self.base["services"].items():
            actual = set()
            for mount in svc["tmpfs"]:
                target, options = mount.split(":", 1)
                actual.add(target)
                for flag in ("noexec", "nosuid", "nodev", "mode=1777"):
                    self.assertIn(flag, options.split(","))
                self.assertRegex(options, r"(?:^|,)size=(?:16|64|128)m(?:,|$)")
            self.assertEqual(expected_tmp[name], actual)
            if name != "postgres":
                self.assertNotIn("volumes", svc)
        self.assertEqual(["pgdata:/var/lib/postgresql/data", "./scripts/init-postgres.sh:/docker-entrypoint-initdb.d/10-fuse.sh:ro"], self.base["services"]["postgres"]["volumes"])

    def test_local_logs_have_bounded_rotation(self):
        for svc in self.base["services"].values():
            self.assertEqual({"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}}, svc["logging"])

    def test_readiness_uses_container_loopback_not_published_adapter(self):
        agent = self.base["services"]["agent"]
        self.assertIn("http://127.0.0.1:8001/ready", agent["healthcheck"]["test"][-1])
        self.assertEqual({"postgres": {"condition": "service_healthy"}, "agent": {"condition": "service_healthy"}}, self.base["services"]["backend"]["depends_on"])

    def test_dev_override_only_adds_explicit_loopback_debug_ports(self):
        self.assertEqual({"services": {"postgres": {"ports": ["127.0.0.1:5432:5432"]}, "agent": {"ports": ["127.0.0.1:8001:8001"]}}}, self.dev)

    def test_live_egress_network_must_already_exist_and_be_explicitly_named(self):
        self.assertEqual({"approved_model_egress"}, set(self.live["networks"]))
        network = self.live["networks"]["approved_model_egress"]
        self.assertEqual({"external", "name"}, set(network))
        self.assertIs(True, network["external"])
        self.assertTrue(network["name"].startswith("${FUSE_LIVE_EGRESS_NETWORK:?"))
        self.assertEqual(["kyc", "approved_model_egress"], self.live["services"]["agent"]["networks"])
        self.assertNotIn("networks", self.live["services"]["backend"])

    def test_live_override_only_changes_model_mode_and_adapter_egress(self):
        self.assertEqual({"services", "networks"}, set(self.live))
        self.assertEqual({"agent", "backend"}, set(self.live["services"]))
        agent, backend = self.live["services"]["agent"], self.live["services"]["backend"]
        self.assertEqual({"networks", "environment"}, set(agent))
        self.assertEqual({"environment"}, set(backend))
        self.assertEqual({"FUSE_KYC_MODE": "live", "FUSE_EXPERIMENT_LIVE_ENABLED": "true"}, backend["environment"])
        self.assertEqual("live", agent["environment"]["FUSE_KYC_MODE"])
        self.assertEqual("https://api.openai.com/v1", agent["environment"]["FUSE_LLM_BASE_URL"])
        for key in ("FUSE_LLM_API_KEY", "FUSE_LLM_MODEL"):
            self.assertTrue(agent["environment"][key].startswith("${" + key + ":?"))
        self.assertEqual({"FUSE_KYC_MODE", "FUSE_LLM_BASE_URL", "FUSE_LLM_API_KEY", "FUSE_LLM_MODEL"}, set(agent["environment"]))

    def test_private_mount_override_never_adds_network_or_privilege(self):
        self.assertEqual({"services"}, set(self.private))
        self.assertEqual({"agent", "backend"}, set(self.private["services"]))
        for svc in self.private["services"].values():
            self.assertEqual({"environment", "volumes"}, set(svc))
            self.assertEqual(1, len(svc["volumes"]))
            mount = svc["volumes"][0]
            self.assertEqual("bind", mount["type"])
            self.assertIs(True, mount["read_only"])
            self.assertIs(False, mount["bind"]["create_host_path"])

    def test_duplicate_yaml_keys_are_not_silently_overwritten(self):
        with self.assertRaises(ValueError):
            load_text("services: {}\nservices: {}\n")

    def test_regression_detector_rejects_external_network(self):
        config = copy.deepcopy(self.base)
        config["networks"]["kyc"]["internal"] = False
        self.assertIn("external routing", base_violations(config))

    def test_regression_detector_rejects_adapter_database_network(self):
        config = copy.deepcopy(self.base)
        config["services"]["agent"]["networks"].append("data")
        self.assertIn("network membership", base_violations(config))

    def test_regression_detector_rejects_public_adapter_port(self):
        config = copy.deepcopy(self.base)
        config["services"]["agent"]["ports"] = ["8001:8001"]
        self.assertIn("host exposure", base_violations(config))

    def test_regression_detector_rejects_capabilities_and_host_network(self):
        config = copy.deepcopy(self.base)
        config["services"]["agent"].update(cap_add=["NET_ADMIN"], network_mode="host")
        self.assertIn("privileged or implicit boundary", base_violations(config))

    def test_regression_detector_rejects_broad_env_import(self):
        config = copy.deepcopy(self.base)
        config["services"]["backend"]["env_file"] = ".env"
        self.assertIn("privileged or implicit boundary", base_violations(config))


if __name__ == "__main__":
    unittest.main(verbosity=2)
