"""Tests for the fpdns CLI."""

import sys
import unittest
from io import StringIO
from unittest.mock import patch, MagicMock

from fpdns.cli import main, _process_target
from fpdns.fingerprint import DNSFingerprint


class TestProcessTarget(unittest.TestCase):
    """Unit tests for _process_target helper."""

    def _engine(self):
        return DNSFingerprint(timeout=1)

    def test_ip_fingerprinted_directly(self):
        engine = self._engine()
        with patch.object(engine, "string", return_value="ISC BIND 9.11"):
            lines = _process_target(engine, "1.2.3.4", 53,
                                    short=False, separator=" ", domain_mode=False)
        self.assertEqual(len(lines), 1)
        self.assertIn("1.2.3.4", lines[0])
        self.assertIn("ISC BIND 9.11", lines[0])

    def test_short_format(self):
        engine = self._engine()
        with patch.object(engine, "string", return_value="NSD"):
            lines = _process_target(engine, "1.2.3.4", 53,
                                    short=True, separator=" ", domain_mode=False)
        self.assertTrue(lines[0].startswith("1.2.3.4"))
        self.assertIn("NSD", lines[0])

    def test_hostname_resolved(self):
        engine = self._engine()
        with patch("fpdns.cli.resolve_to_ips", return_value=["10.0.0.1"]):
            with patch.object(engine, "string", return_value="Unbound 1.9"):
                lines = _process_target(engine, "ns1.example.com", 53,
                                        short=False, separator=" ", domain_mode=False)
        self.assertEqual(len(lines), 1)
        self.assertIn("10.0.0.1", lines[0])

    def test_host_not_found(self):
        engine = self._engine()
        with patch("fpdns.cli.resolve_to_ips", return_value=[]):
            with patch("sys.stderr", new_callable=StringIO) as err:
                lines = _process_target(engine, "nxdomain.invalid", 53,
                                        short=False, separator=" ", domain_mode=False)
        self.assertEqual(lines, [])

    def test_domain_mode(self):
        engine = self._engine()
        with patch("fpdns.cli.get_ns_ips", return_value=[("ns1.ex.com", "5.5.5.5")]):
            with patch.object(engine, "string", return_value="BIND"):
                lines = _process_target(engine, "example.com", 53,
                                        short=False, separator=" ", domain_mode=True)
        self.assertEqual(len(lines), 1)
        self.assertIn("5.5.5.5", lines[0])

    def test_multiple_addresses(self):
        engine = self._engine()
        with patch("fpdns.cli.resolve_to_ips", return_value=["1.1.1.1", "2.2.2.2"]):
            with patch.object(engine, "string", return_value="BIND"):
                lines = _process_target(engine, "ns.example.com", 53,
                                        short=False, separator=" ", domain_mode=False)
        self.assertEqual(len(lines), 2)


class TestMainCLI(unittest.TestCase):
    """Integration-style tests for the main() entry point."""

    def _run(self, argv, stdin_data=None):
        """Run main() with the given argv; capture stdout/stderr."""
        out = StringIO()
        err = StringIO()
        old_argv = sys.argv
        old_stdin = sys.stdin
        try:
            sys.argv = ["fpdns"] + argv
            if stdin_data is not None:
                sys.stdin = StringIO(stdin_data)
            with patch("sys.stdout", out), patch("sys.stderr", err):
                try:
                    main()
                except SystemExit:
                    pass
        finally:
            sys.argv = old_argv
            sys.stdin = old_stdin
        return out.getvalue(), err.getvalue()

    def test_no_targets_prints_help(self):
        out, _ = self._run([])
        self.assertIn("usage", out.lower())

    def test_version_flag(self):
        out, err = self._run(["--version"])
        combined = out + err
        self.assertIn(DNSFingerprint.VERSION, combined)

    def test_single_ip_target(self):
        with patch("fpdns.cli._process_target", return_value=["fingerprint (1.2.3.4): BIND"]):
            out, _ = self._run(["1.2.3.4"])
        self.assertIn("BIND", out)

    def test_file_target(self, tmp_path=None):
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("1.2.3.4\n8.8.8.8\n")
            fname = f.name
        try:
            with patch("fpdns.cli._process_target", return_value=["fp: OK"]):
                out, _ = self._run(["--file", fname])
            self.assertIn("fp: OK", out)
        finally:
            os.unlink(fname)

    def test_stdin_dash(self):
        with patch("fpdns.cli._process_target", return_value=["fp: BIND"]):
            out, _ = self._run(["-"], stdin_data="1.2.3.4\n")
        self.assertIn("BIND", out)

    def test_short_flag_passed(self):
        captured = {}

        def fake_process(engine, target, **kwargs):
            captured["short"] = kwargs.get("short")
            return [f"{target}: ok"]

        with patch("fpdns.cli._process_target", side_effect=fake_process):
            self._run(["-s", "1.2.3.4"])
        self.assertTrue(captured.get("short"))

    def test_domain_ns_flag_passed(self):
        captured = {}

        def fake_process(engine, target, **kwargs):
            captured["domain_mode"] = kwargs.get("domain_mode")
            return []

        with patch("fpdns.cli._process_target", side_effect=fake_process):
            with patch("fpdns.cli.get_ns_ips", return_value=[]):
                self._run(["-D", "example.com"])
        self.assertTrue(captured.get("domain_mode"))

    def test_debug_flag_passed(self):
        created = {}

        original_init = DNSFingerprint.__init__

        def capturing_init(self_fp, **kwargs):
            created["debug"] = kwargs.get("debug")
            original_init(self_fp, **kwargs)

        with patch.object(DNSFingerprint, "__init__", capturing_init):
            with patch("fpdns.cli._process_target", return_value=["ok"]):
                self._run(["-d", "1.2.3.4"])
        self.assertTrue(created.get("debug"))
