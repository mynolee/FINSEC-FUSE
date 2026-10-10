#!/usr/bin/env python3
"""Offline harness regression tests. These are NOT real Docker execution proof."""
from contextlib import ExitStack
import errno
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"),
                                                 Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checks = load("container-network-check")
probe = load("container_network_probe")


def target(expected="DENY", marker=False):
    return {"check": "fixture", "address": "172.28.0.2", "port": 18089,
            "expected": expected, "marker": marker}


class ProbeTests(unittest.TestCase):
    def socket(self, error=None, response=probe.MARKER):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.connect.side_effect = error
        sock.recv.return_value = response
        return sock

    def test_real_success_cannot_count_as_network_denial(self):
        sock = self.socket()
        with patch.object(probe.socket, "socket", return_value=sock):
            self.assertEqual(probe.check_target(target())["status"], "FAIL")
        sock.send.assert_not_called()
        sock.sendall.assert_not_called()
        sock.recv.assert_not_called()

    def test_allowed_target_requires_actual_connection(self):
        with patch.object(probe.socket, "socket", return_value=self.socket()):
            self.assertEqual(probe.check_target(target("ALLOW"))["status"], "PASS")
        with patch.object(probe.socket, "socket", return_value=self.socket(TimeoutError())):
            self.assertEqual(probe.check_target(target("ALLOW"))["status"], "FAIL")

    def test_unavailable_wrong_or_truncated_fixture_cannot_be_positive_control(self):
        for data in (b"", b"incorrect-marker", probe.MARKER[:-1]):
            with self.subTest(response=data), patch.object(probe.socket, "socket",
                    return_value=self.socket(response=data)):
                self.assertEqual(probe.check_target(target("ALLOW", marker=True))["status"], "FAIL")

    def test_only_recognized_connection_errors_count_as_denied(self):
        for error in (TimeoutError(), ConnectionRefusedError(errno.ECONNREFUSED, "fixture"),
                      OSError(errno.ENETUNREACH, "fixture")):
            with patch.object(probe.socket, "socket", return_value=self.socket(error)):
                self.assertEqual(probe.check_target(target())["status"], "PASS")
        with patch.object(probe.socket, "socket", return_value=self.socket(OSError(errno.EINVAL, "fixture"))):
            with self.assertRaises(OSError):
                probe.check_target(target())

    def test_public_dns_loopback_metadata_ipv6_targets_never_open_socket(self):
        for address in ("8.8.8.8", "api.openai.com", "127.0.0.1", "169.254.169.254", "::1", "fd00::2", "0.0.0.0"):
            with self.subTest(address=address), patch.object(probe.socket, "socket") as connect:
                with self.assertRaises(ValueError):
                    probe.check_target({**target(), "address": address})
                connect.assert_not_called()

    def test_bad_expectation_or_port_never_opens_socket(self):
        for change in ({"port": 0}, {"port": True}, {"port": 65536}, {"expected": "anything"}):
            with patch.object(probe.socket, "socket") as connect:
                with self.assertRaises(ValueError):
                    probe.check_target({**target(), **change})
                connect.assert_not_called()

    def test_route_parser_requires_active_nonreject_default(self):
        header = "Iface Destination Gateway Flags RefCnt Use Metric Mask\n"
        active = "eth0 00000000 01001CAC 0003 0 0 0 00000000\n"
        subnet = "eth0 00001CAC 00000000 0001 0 0 0 0000FFFF\n"
        reject = "lo 00000000 00000000 0201 0 0 0 00000000\n"
        self.assertEqual(probe.ipv4_default_routes(header + active + subnet + reject), 1)
        self.assertEqual(probe.ipv4_default_routes(header + subnet + reject), 0)
        prefix = "0" * 32 + " 00 " + "0" * 32 + " 00 " + "0" * 32
        self.assertEqual(probe.ipv6_default_routes(prefix + " 00000001 00000000 00000000 00000003 eth0\n"), 1)
        self.assertEqual(probe.ipv6_default_routes(prefix + " ffffffff 00000000 00000000 00200200 lo\n"), 0)


class HarnessTests(unittest.TestCase):
    def result(self):
        return {"checks": [{"check": "fixture", "expected": "DENY", "observed": "DENIED", "status": "PASS"}],
                "ipv4DefaultRoutes": 0, "ipv6DefaultRoutes": 0}

    def test_valid_result_requires_no_active_default_routes(self):
        checks.validate_observation(self.result(), [target()])
        for name in ("ipv4DefaultRoutes", "ipv6DefaultRoutes"):
            for value in (1, -1, False, "0"):
                result = {**self.result(), name: value}
                with self.subTest(field=name, value=value), self.assertRaises(checks.VerificationError):
                    checks.validate_observation(result, [target()])

    def test_missing_failed_inconsistent_or_untrusted_results_cannot_pass(self):
        for change in ({"checks": []}, {"extra": "private-output"}):
            with self.assertRaises(checks.VerificationError):
                checks.validate_observation({**self.result(), **change}, [target()])
        for change in ({"observed": "CONNECTED"}, {"status": "FAIL"}, {"expected": "ALLOW"},
                       {"check": "unknown"}, {"extra": "private-output"}):
            result = self.result()
            result["checks"][0].update(change)
            with self.assertRaises(checks.VerificationError):
                checks.validate_observation(result, [target()])

    def test_non_ci_project_stops_before_any_docker_action(self):
        for project in ("", "production", "fuse-ci-1-1;echo unexpected", "fuse-ci-1-1-other"):
            with patch.dict("os.environ", {"COMPOSE_PROJECT_NAME": project}), patch.object(checks, "docker") as docker:
                with self.assertRaisesRegex(checks.VerificationError, "ISOLATED_CI_PROJECT_REQUIRED"):
                    checks.execute(checks.fresh_summary())
                docker.assert_not_called()

    def test_absent_docker_is_not_run_not_pass(self):
        with patch.dict("os.environ", {"COMPOSE_PROJECT_NAME": "fuse-ci-1-1"}), \
                patch.object(checks.shutil, "which", return_value=None), patch.object(checks, "emit") as emit:
            self.assertEqual(checks.main(), 1)
        report = emit.call_args.args[0]
        self.assertEqual((report["status"], report["reason"]), ("NOT_RUN", "DOCKER_UNAVAILABLE"))
        self.assertEqual(report["services"], {})

    def test_raw_errors_are_never_written_to_summary(self):
        with patch.object(checks, "execute", side_effect=ValueError("private diagnostic")), \
                patch.object(checks, "emit") as emit:
            self.assertEqual(checks.main(), 1)
        self.assertNotIn("private diagnostic", json.dumps(emit.call_args.args[0]))

    def test_probe_has_no_pull_mount_privilege_credentials_or_public_network(self):
        work = checks.IsolatedRun("sha256:" + "a" * 64)
        with patch.object(checks, "docker", return_value="fixture") as docker:
            work.run("agent", "container:" + "b" * 64, "fixture source")
        args = docker.call_args.args
        self.assertIn("--pull=never", args)
        self.assertIn("--read-only", args)
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        self.assertEqual(args[args.index("--user") + 1], "10001:10001")
        self.assertEqual(args[args.index("--network") + 1], "container:" + "b" * 64)
        for forbidden in ("--privileged", "--cap-add", "--mount", "--volume", "--env", "--env-file", "--publish"):
            self.assertNotIn(forbidden, args)

    def test_fixture_network_is_always_new_internal_and_labeled(self):
        work = checks.IsolatedRun("sha256:" + "a" * 64)
        with patch.object(checks, "docker", return_value="c" * 64) as docker:
            work.create_network()
        self.assertEqual(docker.call_args.args[:6], ("network", "create", "--internal", "--driver", "bridge", "--label"))
        self.assertIn(work.label, docker.call_args.args)

    def test_cleanup_only_targets_unique_test_resources_and_verifies_absence(self):
        work = checks.IsolatedRun("sha256:" + "a" * 64)
        work.containers = [work.prefix + "-fixture", work.prefix + "-agent"]
        work.network = "c" * 64
        with patch.object(checks.subprocess, "run") as run, patch.object(checks, "docker", return_value=""):
            self.assertTrue(work.cleanup())
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands, [["docker", "rm", "--force", name] for name in reversed(work.containers)] +
                         [["docker", "network", "rm", work.network]])
        with patch.object(checks.subprocess, "run"), patch.object(checks, "docker", return_value="leftover"):
            self.assertFalse(work.cleanup())

    def test_summary_does_not_promote_untested_live_or_ipv6_scope(self):
        summary = checks.fresh_summary()
        for key in ("liveEgressPolicy", "metadataAndHostGateway", "ipv6SocketIsolation"):
            self.assertEqual(summary[key], "NOT_RUN")
        self.assertFalse(summary["providerCalls"])
        self.assertFalse(summary["publicInternetConnections"])

    def test_safe_summary_permissions_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe" / "summary.json"
            checks.emit(checks.fresh_summary(), path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            link = path.parent / "link.json"
            link.symlink_to(path)
            with self.assertRaises(checks.VerificationError):
                checks.emit(checks.fresh_summary(), link)


class OrchestrationTests(unittest.TestCase):
    def simulated_run(self, *, unavailable=False, cleanup=True, app_changed=False):
        project = "fuse-ci-1-1"
        containers = {service: {"id": character * 64, "image": "sha256:" + "a" * 64,
                      "networks": {project + "_" + network: {"IPAddress": "172.28.0." + str(index + 2)}
                                   for network in networks}}
                      for index, ((service, networks), character) in enumerate(zip(checks.SERVICES.items(), "abcd"))}
        work = MagicMock()
        work.prefix = "fixture-network"
        work.create_network.return_value = "e" * 64
        work.run.return_value = "f" * 64
        work.cleanup.return_value = cleanup

        def observe(_suffix, _network, targets):
            return {"checks": [{"check": target["check"], "expected": target["expected"],
                                "observed": "CONNECTED" if target["expected"] == "ALLOW" else "DENIED",
                                "status": "FAIL" if unavailable else "PASS"} for target in targets],
                    "ipv4DefaultRoutes": 0, "ipv6DefaultRoutes": 0}

        work.probe.side_effect = observe
        with ExitStack() as stack:
            stack.enter_context(patch.dict("os.environ", {"COMPOSE_PROJECT_NAME": project}))
            stack.enter_context(patch.object(checks.shutil, "which", return_value="/usr/bin/docker"))
            inspect = stack.enter_context(patch.object(checks, "inspect_services",
                side_effect=[containers, {} if app_changed else containers]))
            stack.enter_context(patch.object(checks, "IsolatedRun", return_value=work))
            stack.enter_context(patch.object(checks, "inspect_container", return_value={
                "networks": {work.prefix: {"IPAddress": "172.29.0.2"}}}))
            stack.enter_context(patch.object(checks.time, "sleep"))
            emit = stack.enter_context(patch.object(checks, "emit"))
            exit_code = checks.main()
        return exit_code, emit.call_args.args[0], work, inspect

    def test_success_requires_all_four_service_namespaces_and_both_fixture_controls(self):
        code, result, work, inspect = self.simulated_run()
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(set(result["services"]), set(checks.SERVICES))
        self.assertEqual(sum(len(service["checks"]) for service in result["services"].values()), 14)
        self.assertEqual(len(result["positiveControls"]), 2)
        self.assertTrue(result["cleanupVerified"])
        self.assertTrue(result["applicationNetworksUnchanged"])
        self.assertEqual(inspect.call_count, 2)
        calls = work.probe.call_args_list
        self.assertEqual([call.args[0] for call in calls],
                         ["control-start-0", "agent", "backend", "frontend", "postgres", "control-end"])
        for call in calls[1:-1]:
            self.assertTrue(call.args[1].startswith("container:"))
        work.cleanup.assert_called_once()

    def test_unavailable_fixture_fails_before_any_denial_claim_and_cleans_up(self):
        code, result, work, _ = self.simulated_run(unavailable=True)
        self.assertEqual((code, result["status"]), (1, "FAIL"))
        self.assertEqual(result["services"], {})
        self.assertEqual(result["positiveControls"], [])
        self.assertTrue(all(call.args[0].startswith("control-start-") for call in work.probe.call_args_list))
        work.cleanup.assert_called_once()

    def test_successful_probes_cannot_mask_cleanup_failure(self):
        code, result, _, _ = self.simulated_run(cleanup=False)
        self.assertEqual((code, result["status"]), (1, "FAIL"))
        self.assertEqual(result["reason"], "FIXTURE_CLEANUP_NOT_VERIFIED")

    def test_changed_app_topology_fails_and_still_cleans_up(self):
        code, result, work, _ = self.simulated_run(app_changed=True)
        self.assertEqual((code, result["status"]), (1, "FAIL"))
        self.assertEqual(result["reason"], "APPLICATION_CHANGED_DURING_TEST")
        self.assertFalse(result["applicationNetworksUnchanged"])
        work.cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
