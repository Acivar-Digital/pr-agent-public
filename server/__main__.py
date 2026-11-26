"""Server entrypoint: resolve this machine's identity, then serve.

`python -m server` is what `pr-agent.service` runs. The bind address comes from
config/location.json rather than the unit file, so dev and production cannot
drift apart on the command line, and access logging stays on.
"""

from __future__ import annotations

import uvicorn

from server.location import load_location


def main() -> None:
    location = load_location()
    uvicorn.run(
        "server.app:app",
        host=location.host,
        port=location.port,
        access_log=True,
    )


if __name__ == "__main__":
    main()
