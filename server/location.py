"""Environment identity for pr-agent-vps.

`config/location.json` declares which machine this is and where the peer lives;
the repo's parent directory arbitrates whether that declaration is trustworthy.
Local filesystem paths are deliberately absent — the modules that use them own them.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

EnvironmentName = Literal["dev", "production"]

#: Repository parent directory -> the environment it identifies.
PARENT_ENVIRONMENTS: dict[str, EnvironmentName] = {
    "services": "production",
    "arthityap": "dev",
}

LOCATION_DIR = "config"
LOCATION_FILENAME = "location.json"

log = logging.getLogger(__name__)


class LocationConfigError(RuntimeError):
    """config/location.json is missing, invalid, or contradicts the filesystem."""


class PeerEnvironment(BaseModel):
    """The other deployment target. `root` is remote, so it must be declared."""

    model_config = ConfigDict(extra="forbid")

    environment: EnvironmentName
    ssh_host: str | None = None
    root: str
    host: str
    port: int = Field(ge=1, le=65535)


class TestingConfig(BaseModel):
    """Optional local test server coordinates."""

    model_config = ConfigDict(extra="forbid")

    test_port: int = Field(ge=1, le=65535)
    test_base_url: str


class LocationConfig(BaseModel):
    """Contents of config/location.json."""

    model_config = ConfigDict(extra="forbid")
    profile: str
    environment: EnvironmentName
    host: str
    port: int = Field(ge=1, le=65535)
    parent_dir: str
    working_folder: str
    peer: PeerEnvironment
    testing: TestingConfig | None = None


def project_root() -> Path:
    """Repository root, anchored to this file rather than the process cwd."""
    return Path(__file__).resolve().parent.parent


def detect_environment(root: Path) -> EnvironmentName | None:
    """Environment implied by the repo's parent directory, or None if unknown.

    None rather than an exception is deliberate: an unrecognised checkout (CI
    path, custom worktree) must still boot on its declared identity.
    """
    return PARENT_ENVIRONMENTS.get(root.resolve().parent.name)


def load_location(path: Path | None = None) -> LocationConfig:
    """Load and validate config/location.json.

    Raises:
        LocationConfigError: if the file is missing, unparseable, or declares an
            environment the filesystem contradicts — the signature of a config
            copied between machines.
    """
    target = path or project_root() / LOCATION_DIR / LOCATION_FILENAME
    if not target.is_file():
        raise LocationConfigError(
            f"Missing {target}. Copy {LOCATION_DIR}/{LOCATION_FILENAME}.example to "
            f"{LOCATION_DIR}/{LOCATION_FILENAME} and set it for this machine."
        )
    try:
        config = LocationConfig.model_validate(json.loads(target.read_text("utf-8")))
    except (json.JSONDecodeError, ValidationError) as exc:
        raise LocationConfigError(f"Invalid {target}: {exc}") from exc

    _verify_environment(target, config)
    return config


def _verify_environment(target: Path, config: LocationConfig) -> None:
    repo_root = target.parent.parent
    detected = detect_environment(repo_root)
    if detected is None:
        log.warning(
            "%s sits under unrecognised parent %r; trusting declared environment %r.",
            target,
            repo_root.parent.name,
            config.environment,
        )
    elif config.environment != detected:
        raise LocationConfigError(
            f"{target} declares environment {config.environment!r} but the filesystem "
            f"indicates {detected!r}; the file was probably copied between machines."
        )


def main() -> int:
    """Print the resolved identity for pre-flight verification during a deploy."""
    try:
        config = load_location()
    except LocationConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(
        f"environment={config.environment} host={config.host} "
        f"port={config.port} profile={config.profile}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
