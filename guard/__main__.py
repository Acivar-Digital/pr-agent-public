"""Allow `python -m guard` execution."""

from __future__ import annotations

from guard.guardrail import main

if __name__ == "__main__":
    raise SystemExit(main())
