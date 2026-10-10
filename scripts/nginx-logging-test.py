#!/usr/bin/env python3
"""Static Nginx log privacy contract and mutation checks, NOT runtime proof.

No Docker, HTTP requests, credentials, environment files, or private assets are
used. Runtime acceptance still requires synthetic query/header/body/CRLF probes
and a whole-sink log scan on the built containers, including upstream failures.
"""
from pathlib import Path
import shlex
import unittest

ROOT = Path(__file__).resolve().parents[1]


def directives(source):
    """Parse this repository's small Nginx configs, retaining directive scope."""
    lexer = shlex.shlex(source, posix=True, punctuation_chars="{};")
    lexer.whitespace_split = True
    lexer.commenters = "#"
    tokens = list(lexer)
    position = 0

    def block(nested=False):
        nonlocal position
        nodes = []
        while position < len(tokens):
            words = []
            while position < len(tokens) and tokens[position] not in (";", "{", "}"):
                token = tokens[position]
                if token and set(token).issubset(set("{};")):
                    raise ValueError("unsupported compound punctuation")
                words.append(token)
                position += 1
            if position == len(tokens):
                raise ValueError("unterminated directive")
            end = tokens[position]
            position += 1
            if end == "}":
                if words or not nested:
                    raise ValueError("unexpected closing block")
                return nodes
            if not words:
                raise ValueError("empty directive")
            nodes.append((words[0], words[1:], block(True) if end == "{" else None))
        if nested:
            raise ValueError("unclosed block")
        return nodes

    return block()


def frontend_logging_is_private(source):
    try:
        nodes = directives(source)
    except ValueError:
        return False
    # The image installs this file as the entire default virtual server.
    if len(nodes) != 1 or nodes[0][0:2] != ("server", []):
        return False
    server = nodes[0][2]
    if server is None:
        return False
    expected = {"access_log": ["off"], "error_log": ["/dev/stderr", "crit"]}
    for name, arguments in expected.items():
        if [(args, children) for directive, args, children in server if directive == name] != [(arguments, None)]:
            return False

    def safe_scope(scope):
        for name, arguments, children in scope:
            # Unknown includes could override the reviewed inherited policy.
            if name == "include":
                return False
            if name in expected and (arguments != expected[name] or children is not None):
                return False
            if children is not None and not safe_scope(children):
                return False
        return True

    return safe_scope(server)


class NginxLoggingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = (ROOT / "frontend/nginx.conf").read_text(encoding="utf-8")

    def test_frontend_explicit_server_scope_logging_policy(self):
        self.assertTrue(frontend_logging_is_private(self.config))

    def test_image_installs_reviewed_frontend_config(self):
        dockerfile = (ROOT / "frontend/Dockerfile").read_text(encoding="utf-8")
        copies = [line.strip() for line in dockerfile.splitlines() if line.strip().startswith("COPY ") and "/etc/nginx/" in line]
        self.assertEqual(["COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf"], copies)

    def test_removing_either_policy_is_rejected(self):
        for directive in ("access_log off;", "error_log /dev/stderr crit;"):
            with self.subTest(directive=directive):
                self.assertFalse(frontend_logging_is_private(self.config.replace(directive, "")))

    def test_commented_policy_is_not_counted(self):
        self.assertFalse(frontend_logging_is_private(self.config.replace("access_log off;", "# access_log off;")))

    def test_location_only_policy_is_insufficient(self):
        modified = self.config.replace("access_log off;", "")
        modified = modified.replace("location /api/ {", "location /api/ {\n    access_log off;")
        self.assertFalse(frontend_logging_is_private(modified))

    def test_nested_access_log_override_is_rejected(self):
        modified = self.config.replace("location /api/ {", "location /api/ {\n    access_log /dev/stdout combined;")
        self.assertFalse(frontend_logging_is_private(modified))

    def test_nested_error_log_override_is_rejected(self):
        modified = self.config.replace("location / {", "location / {\n    error_log /dev/stderr error;")
        self.assertFalse(frontend_logging_is_private(modified))

    def test_more_verbose_error_severities_are_rejected(self):
        for severity in ("error", "warn", "notice", "info", "debug", ""):
            with self.subTest(severity=severity):
                self.assertFalse(frontend_logging_is_private(self.config.replace("/dev/stderr crit", "/dev/stderr " + severity)))

    def test_duplicate_logging_directive_is_rejected(self):
        self.assertFalse(frontend_logging_is_private(self.config.replace("access_log off;", "access_log off;\n  access_log /dev/stdout combined;")))

    def test_hidden_include_override_is_rejected(self):
        self.assertFalse(frontend_logging_is_private(self.config.replace("location / {", "location / {\n    include hidden.conf;")))

    def test_parser_rejects_malformed_config(self):
        for source in (self.config[:-2], self.config + "}", "server { access_log off }", "server;"):
            with self.subTest(source_type="malformed"):
                self.assertFalse(frontend_logging_is_private(source))

    def test_original_inherited_logging_configuration_is_rejected(self):
        original = self.config.replace("access_log off;", "").replace("error_log /dev/stderr crit;", "")
        self.assertFalse(frontend_logging_is_private(original))


if __name__ == "__main__":
    unittest.main()
