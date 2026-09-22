import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from defensive_mcp_audit.mcp_config import parse_mcp_configs


class ConfigResilienceTests(unittest.TestCase):
    def test_explicit_empty_paths_do_not_discover_host_configs(self):
        with patch('defensive_mcp_audit.mcp_config.discover_mcp_config_paths') as discover:
            self.assertEqual(parse_mcp_configs([]), ([], []))
            discover.assert_not_called()

    def test_malformed_metadata_and_encoding_do_not_abort_other_configs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad_encoding = root / 'invalid.json'
            bad_encoding.write_bytes(b'\xff')
            metadata = root / 'SERVER_METADATA.json'
            config = root / 'valid.json'
            config.write_text(json.dumps({'mcpServers': {'valid': {'command': 'server'}}}))
            for invalid in [[], None, 'string', 42]:
                with self.subTest(payload=invalid):
                    metadata.write_text(json.dumps(invalid))
                    servers, _ = parse_mcp_configs([root, bad_encoding, config])
                    self.assertEqual([s['name'] for s in servers], ['valid'])

    def test_auth_headers_detected_even_when_env_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / 'mcp.json'
            config.write_text(json.dumps({'mcpServers': {'remote': {
                'url': 'https://example.test', 'env': ['invalid'],
                'headers': {'Authorization': 'synthetic-test-value'},
            }}}))
            servers, _ = parse_mcp_configs([config])
            self.assertTrue(servers[0]['has_auth_hints'])
            self.assertNotIn('synthetic-test-value', json.dumps(servers))
