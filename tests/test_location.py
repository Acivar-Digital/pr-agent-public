"""Unit tests for server.location.

Each test builds a throwaway repo tree so the real parent-directory detection
runs, rather than mocking the filesystem it is supposed to arbitrate.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from server.location import LocationConfigError, load_location

VALID = {
    "profile": "test",
    "environment": "dev",
    "host": "127.0.0.1",
    "port": 8446,
    "parent_dir": "arthityap",
    "working_folder": "pr-agent-vps",
    "peer": {
        "environment": "production",
        "ssh_host": "your-vps-host",
        "root": "/srv/pr-agent-vps",
        "host": "127.0.0.1",
        "port": 8446,
    },
}


def write_config(repo: Path, **overrides: object) -> Path:
    """Create ``<repo>/config/location.json`` and return its path."""
    config_dir = repo / "config"
    config_dir.mkdir(parents=True)
    path = config_dir / "location.json"
    path.write_text(json.dumps({**VALID, **overrides}), encoding="utf-8")
    return path


class LoadLocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_valid_dev_config(self) -> None:
        path = write_config(self.tmp / "arthityap" / "pr-agent-vps")
        self.assertEqual(load_location(path).environment, "dev")

    def test_valid_production_config(self) -> None:
        path = write_config(
            self.tmp / "services" / "pr-agent-vps",
            environment="production",
            parent_dir="services",
        )
        self.assertEqual(load_location(path).environment, "production")

    def test_copy_guard_refuses_mismatched_environment(self) -> None:
        """A prod config dropped into a dev checkout must not boot."""
        path = write_config(
            self.tmp / "arthityap" / "pr-agent-vps",
            environment="production",
            parent_dir="services",
        )
        with self.assertRaises(LocationConfigError):
            load_location(path)

    def test_unrecognised_parent_warns_and_trusts_declaration(self) -> None:
        path = write_config(
            self.tmp / "ci-runner" / "pr-agent-vps",
            environment="production",
            parent_dir="ci-runner",
        )
        with self.assertLogs("server.location", level="WARNING"):
            config = load_location(path)
        self.assertEqual(config.environment, "production")

    def test_missing_config_raises(self) -> None:
        missing = self.tmp / "arthityap" / "pr-agent-vps" / "config" / "location.json"
        with self.assertRaises(LocationConfigError):
            load_location(missing)

    def test_malformed_config_raises(self) -> None:
        repo = self.tmp / "arthityap" / "pr-agent-vps"
        config_dir = repo / "config"
        config_dir.mkdir(parents=True)
        (config_dir / "location.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(LocationConfigError):
            load_location(config_dir / "location.json")


if __name__ == "__main__":
    unittest.main()
