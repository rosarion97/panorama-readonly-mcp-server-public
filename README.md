# Panorama Read-Only MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that
lets Claude **query — and only query** — a **Palo Alto Networks Panorama**
management server over stdio, using the PAN-OS XML API. It can retrieve system
info, list managed firewalls, pull running or candidate configuration, view
security policies, run operational `show` commands, retrieve logs, pull
reports, and query individual firewalls through Panorama — all without making
any changes.

Sister to the read/write
[`palo_alto-mcp-server`](https://github.com/rosarion97/palo_alto-mcp-server-public)
(direct firewall management) and the other `rosarion97` MCP servers — same
house style.

> Not affiliated with or endorsed by Palo Alto Networks. Use at your own risk.
> **Read-only is not the same as harmless** — configuration, policies, and logs
> can contain sensitive operational data; scope the admin role accordingly.

---

## Pick a backend

The server ships in two interchangeable container flavors running the
**byte-identical** `server.py`; choose whichever matches your toolchain:

| | When to use | Setup guide |
|---|---|---|
| 🐳 **Docker** | You use Docker Desktop + the MCP Toolkit | [`docker/README.md`](docker/README.md) |
| 🦭 **Podman** | You want rootless containers / no Docker Desktop | [`podman/README.md`](podman/README.md) |

Each guide is self-contained (build → secrets → register with Claude
Desktop / Claude Code → verify). The only differences are how the image is
built and how secrets are stored; the tools, guarantees, and behavior are the
same.

---

## What it does

- **23 read tools** — system/HA info, managed-firewall inventory, device
  groups and templates, running/candidate config by XPath, security policies,
  objects, guarded operational `show` commands, logs, reports, config export,
  and per-firewall queries proxied through Panorama.
- **One info resource** (`config://panorama-info`) — connection details built
  from env values; performs no network I/O and never echoes the API key.

Full tool tables live in the backend READMEs.

---

## Read-only guarantee (in one paragraph)

The PAN-OS XML API transports every call as an HTTP POST, so the guarantee is
enforced at the **operation** level: all requests route through one shared
helper (`_panorama_request`) that only ever issues read operation types
(`op` — guarded to `<show>` commands by an allowlist, `config` with
`action=show`/`get`, `log`, `report`, `export`, `version`). No
`type=commit` or `action=set/edit/delete` exists anywhere in the codebase, and
`run_show_command` rejects anything outside `<show>` via blocked-prefix
validation. `PANORAMA_HOST` pins the server to one Panorama (no tool takes a
host parameter), XPath and name inputs are validated, and the API key lives in
a secret store or a `chmod 600` `.env` — never in chat or error strings. See the backend READMEs'
security sections for details.

---

## Repository layout

```
.
├── README.md      # you are here — overview + backend chooser
├── docker/        # Docker variant + custom-catalog.yaml (Docker MCP Toolkit)
└── podman/        # Podman variant, rootless
```

`docker/server.py` and `podman/server.py` are kept byte-identical
(`diff -q docker/server.py podman/server.py`).

---

## Configuration

All configuration is via environment variables (container secrets or an
`--env-file`). Required: `PANORAMA_HOST`, `PANORAMA_API_KEY`. Optional:
`PANORAMA_VERIFY_SSL`. See `docker/.env.example` for details and defaults.

The API key is generated **out of band** with `curl` (backend README, Step 0) —
never through this server. Use a dedicated admin account with a read-only
custom Admin Role.

---

## License

Provided as-is for integrating Panorama with MCP clients. Use at your own risk.
Not affiliated with or endorsed by Palo Alto Networks.
