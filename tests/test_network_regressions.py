import unittest
from types import SimpleNamespace
from unittest.mock import patch

from defensive_mcp_audit.network import (
    _parse_netstat_line,
    discover_listening_services,
    is_localhost_binding,
    is_risky_binding,
)


class BindingClassificationRegressionTests(unittest.TestCase):
    def test_wildcard_and_loopback_addresses(self):
        for address in ("0.0.0.0", "::", "[::]", "*", "0:0:0:0:0:0:0:0"):
            with self.subTest(address=address):
                self.assertTrue(is_risky_binding(address))
        for address in ("127.0.0.1", "127.0.0.53%lo", "::1", "[::1%lo0]"):
            with self.subTest(address=address):
                self.assertFalse(is_risky_binding(address))
                self.assertTrue(is_localhost_binding(address))

    def test_explicit_private_public_and_scoped_non_loopback_addresses_are_risky(self):
        for address in (
            "192.168.1.20",
            "10.0.0.7",
            "8.8.8.8",
            "2001:4860:4860::8888",
            "fe80::1%eth0",
            "[fd00::1234]",
        ):
            with self.subTest(address=address):
                self.assertTrue(is_risky_binding(address))
                self.assertFalse(is_localhost_binding(address))

    def test_ipv4_mapped_ipv6_uses_embedded_ipv4_loopback_semantics(self):
        self.assertFalse(is_risky_binding("::ffff:127.0.0.1"))
        self.assertFalse(is_risky_binding("[::ffff:127.20.30.40]"))
        self.assertTrue(is_localhost_binding("::ffff:127.0.0.1"))
        self.assertTrue(is_risky_binding("::ffff:192.168.1.2"))
        self.assertTrue(is_risky_binding("::ffff:8.8.8.8"))

    def test_bracket_and_scope_cleanup_is_not_character_stripping(self):
        self.assertTrue(is_risky_binding("10.0.0.1%lo"))
        self.assertTrue(is_risky_binding("[2001:db8::1%en0]"))
        self.assertFalse(is_risky_binding("localhost"))


class NetworkParserRegressionTests(unittest.TestCase):
    def test_headerless_ss_output_is_not_discarded(self):
        output = (
            "LISTEN 0 128 192.168.1.15:8080 0.0.0.0:* "
            'users:(("uvicorn",pid=2345,fd=3))\n'
            "LISTEN 0 64 [::1]:9000 *:*\n"
        )
        services = discover_listening_services(ss_output=output)
        self.assertEqual([service["port"] for service in services], [8080, 9000])
        self.assertEqual(services[0]["address"], "192.168.1.15")
        self.assertTrue(services[0]["risky_binding"])
        self.assertEqual(services[0]["pid"], "2345")
        self.assertTrue(services[1]["localhost_binding"])
        self.assertFalse(services[1]["risky_binding"])

    def test_ss_with_netid_column_is_supported(self):
        services = discover_listening_services(
            ss_output="tcp LISTEN 0 128 [2001:db8::10]:443 [::]:*\n"
        )
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["address"], "2001:db8::10")
        self.assertEqual(services[0]["port"], 443)
        self.assertTrue(services[0]["risky_binding"])

    def test_linux_netstat_uses_local_address_column(self):
        line = "tcp 0 0 192.168.1.4:5000 0.0.0.0:* LISTEN"
        with patch("defensive_mcp_audit.network.platform.system", return_value="Linux"):
            parsed = _parse_netstat_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["address"], "192.168.1.4")
        self.assertEqual(parsed["port"], 5000)
        self.assertTrue(parsed["risky_binding"])

    def test_windows_netstat_format(self):
        line = "  TCP    [::]:135    [::]:0    LISTENING    1234"
        with patch("defensive_mcp_audit.network.platform.system", return_value="Windows"):
            parsed = _parse_netstat_line(line)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["address"], "::")
        self.assertEqual(parsed["port"], 135)
        self.assertTrue(parsed["risky_binding"])

    def test_darwin_dotted_endpoint_and_wildcard(self):
        lines = (
            "tcp4 0 0 127.0.0.1.5000 *.* LISTEN",
            "tcp6 0 0 *.22 *.* LISTEN",
            "tcp6 0 0 fe80::1%en0.8443 *.* LISTEN",
        )
        with patch("defensive_mcp_audit.network.platform.system", return_value="Darwin"):
            parsed = [_parse_netstat_line(line) for line in lines]
        self.assertEqual(parsed[0]["address"], "127.0.0.1")
        self.assertEqual(parsed[0]["port"], 5000)
        self.assertFalse(parsed[0]["risky_binding"])
        self.assertEqual(parsed[1]["address"], "*")
        self.assertEqual(parsed[1]["port"], 22)
        self.assertTrue(parsed[1]["risky_binding"])
        self.assertEqual(parsed[2]["address"], "fe80::1%en0")
        self.assertEqual(parsed[2]["port"], 8443)
        self.assertTrue(parsed[2]["risky_binding"])

    def test_platform_commands_are_read_only_and_darwin_flags_are_valid(self):
        result = SimpleNamespace(
            returncode=0,
            stdout="Active Internet connections\n"
            "tcp4 0 0 10.1.2.3.8080 *.* LISTEN\n",
        )
        with (
            patch("defensive_mcp_audit.network.platform.system", return_value="Darwin"),
            patch("defensive_mcp_audit.network.shutil.which", side_effect=lambda name: "/usr/bin/netstat" if name == "netstat" else None),
            patch("defensive_mcp_audit.network.subprocess.run", return_value=result) as run,
        ):
            services = discover_listening_services()
        run.assert_called_once_with(
            ["netstat", "-an", "-p", "tcp"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(services[0]["address"], "10.1.2.3")
        self.assertTrue(services[0]["risky_binding"])

    def test_linux_fallback_command_and_windows_listener_command(self):
        result = SimpleNamespace(returncode=0, stdout="")
        for system, expected in (("Linux", ["netstat", "-tln"]), ("Windows", ["netstat", "-ano"])):
            with self.subTest(system=system):
                with (
                    patch("defensive_mcp_audit.network.platform.system", return_value=system),
                    patch("defensive_mcp_audit.network.shutil.which", side_effect=lambda name: "/usr/bin/netstat" if name == "netstat" else None),
                    patch("defensive_mcp_audit.network.subprocess.run", return_value=result) as run,
                    patch("defensive_mcp_audit.network.sys.stderr"),
                ):
                    discover_listening_services()
                self.assertEqual(run.call_args.args[0], expected)


if __name__ == "__main__":
    unittest.main()
