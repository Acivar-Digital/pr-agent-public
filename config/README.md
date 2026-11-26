# config/

This directory holds **per-machine configuration** that is intentionally
**not committed to git**. All paths are **relative to the repository root**.

| File | Purpose | Tracked? |
|------|---------|----------|
| `location.json.example` | Schema template and developer copy-paste source | Yes (committed) |
| `location.json` | This machine's actual environment identity | **No (gitignored)** |

The `.env` file lives at the **project root** (not in `config/`) and is also
untracked — see `.env.example` there.

---

## Environment detection

`server/location.py` resolves the environment from the **filesystem**, not from
an environment variable or a hostname:

| Check | Result |
|-------|--------|
| Parent directory is `arthityap` | `environment: dev` |
| Parent directory is `services` | `environment: production` |
| anything else | a warning is logged; the declared `environment` is trusted |

This means a checkout of the repo under `~/arthityap/pr-agent-vps` is always dev,
and one under `/services/pr-agent-vps` is always production, regardless of what
the file claims — except when the parent directory is not one of the two above,
in which case the file is trusted so that CI paths and custom worktrees still boot.

`config/location.json` is only read by **`server/location.py`**. It is the single
authority for this machine's declared environment name, bind host/port, profile,
working directory, and peer-environment descriptor.

---

## Setup (one time per machine)

```bash
cp config/location.json.example config/location.json
# then edit config/location.json and set `environment` to dev or production
# and set the peer block to describe the *other* machine
```

`config/location.json` is read only when `server/location.py` loads it. Nothing
else in the repo reads it. The deploy target is a fixed `your-vps-host:/srv/pr-agent-vps`
and is not derived from this file.

`server/location.py` also has a small CLI helper for manual verification:

```bash
uv run python -m server.location
# prints the resolved environment, host, and port
```

---

## Schema

`config/location.json` is plain JSON and is validated by Pydantic on load.

| Field | Type | Purpose |
|-------|------|---------|
| `profile` | string | Logical grouping name (e.g. `dev`, `vps-prod`). For the operator's reference only — not used to select behavior. |
| `environment` | `"dev"` or `"production"` | Which environment this checkout is. |
| `host` | string | Bind host for the pr-agent REST API on this machine (e.g. `127.0.0.1`). |
| `port` | integer | Bind port for the pr-agent REST API on this machine (e.g. `8446`). |
| `parent_dir` | string | Name of the directory directly containing the repo root (e.g. `arthityap`, `services`). Descriptive only — `detect_environment` reads the real directory rather than this field. |
| `working_folder` | string | The repo's own directory name (e.g. `pr-agent-vps`). |
| `peer.environment` | `"dev"` or `"production"` | The other environment's identifier (e.g. `production` on dev, `dev` on prod). |
| `peer.ssh_host` | string or null | SSH alias/hostname for the peer machine. `null` when not reachable. |
| `peer.root` | string | Absolute path of the peer's repo root on the peer machine (e.g. `/srv/pr-agent-vps` on the VPS). |
| `peer.host` | string | The peer machine's bind host for pr-agent (e.g. `127.0.0.1`). |
| `peer.port` | integer | The peer machine's bind port for pr-agent (e.g. `8446`). |

When `environment` is `"production"`, the process binds to the configured host/port
and the filesystem check above guards against the file having been copied from dev.
When `environment` is `"dev"`, the process runs against the local development
database with the configured host/port. The *peer* block is descriptive metadata for
the other environment; it is not used to pick paths, and nothing in `server/`
reads it.

---

## What is tracked vs. untracked

- **Tracked (committed):** `config/README.md`, `config/location.json.example`
- **Untracked (gitignored):** `config/location.json`

The `.gitignore` entry is exactly:

```
config/location.json
```

so the file cannot be accidentally committed. If a developer changes their
environment, they edit their local `config/location.json`; the change never
propagates through git.

---

## Adding a new environment

1. Update `EnvironmentName` in `server/location.py` with the new literal.
2. Add the new parent directory to `PARENT_ENVIRONMENTS` in the same file.
3. Add the new machine's values to its own local `config/location.json`.
4. Document the new environment in this file.

The repo currently recognizes two parent directories: `arthityap` (dev) and
`services` (production).

---

## Production deployment

`admin/sync.sh` is the only supported way to update the VPS. It refuses to run
unless the local parent directory is `arthityap` and the peer declared in
`config/location.json` has `environment: production`.

The remote unit (`pr-agent.service`) starts the server with `python -m server`,
so the bind host and port come from `config/location.json` on the peer rather
than from the unit file. If a future package needs a second environment-specific
file in `config/`, add it alongside `location.json` and keep it untracked in the
same way; update the `.gitignore` entry accordingly.