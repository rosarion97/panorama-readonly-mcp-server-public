# Panorama Read-Only MCP Server (Podman)

A Model Context Protocol (MCP) server that lets Claude query a **Palo Alto Networks Panorama** management server in **read-only mode** using the PAN-OS XML API. It can retrieve system info, list managed firewalls, pull running or candidate configuration, view security policies, run operational "show" commands, retrieve logs, pull reports, and query individual firewalls through Panorama — all without making any changes.

This variant is built and run with **Podman**. The recommended setup stores secrets in Podman's secret store and injects them into the container at runtime as environment variables, so Claude Desktop's configuration file references secrets by name only and never contains the API key, hostname, or any other credential. A plaintext `.env` option is also available for quick local testing or older Podman releases (see Step 4).

> New here? Start with the [repo overview](../README.md). Looking for the Docker
> version? It's in [`../docker/`](../docker/README.md) and uses the Docker MCP Toolkit.

> Not affiliated with or endorsed by Palo Alto Networks. Use at your own risk.

---

## What It Does

This server exposes 23 read-only tools to Claude via MCP:

| Tool | Description |
|------|-------------|
| `get_system_info` | Panorama/firewall system info (hostname, model, serial, version, uptime) |
| `get_panorama_status` | Panorama HA status and platform health |
| `list_managed_devices` | List all managed firewalls with details |
| `get_device_groups` | List device groups and their assigned firewalls |
| `get_templates` | List templates and template stacks |
| `get_running_config` | Retrieve active (running) config for any XPath under `/config` |
| `get_candidate_config` | Retrieve candidate (uncommitted) config for any XPath under `/config` |
| `get_security_rules` | Security policy rules from device groups or firewalls |
| `get_nat_rules` | NAT rules from device groups or firewalls |
| `get_address_objects` | Address objects (shared, device-group, or firewall) |
| `get_address_groups` | Address group objects |
| `get_service_objects` | Service objects (protocol/port definitions) |
| `get_security_profiles` | Security profiles (AV, anti-spyware, vulnerability, URL filtering, etc.) |
| `run_show_command` | Run any read-only `<show>` operational command |
| `get_logs` | Retrieve logs (traffic, threat, system, config, URL, WildFire, etc.) |
| `get_report` | Retrieve predefined, dynamic, or custom reports |
| `get_predefined_objects` | Retrieve predefined applications, services, or threats |
| `get_ha_status` | High-availability status |
| `get_job_status` | Check async job status |
| `export_device_state` | Export running config for backup/review |
| `get_config_audit` | Show uncommitted changes |
| `get_commit_locks` | Show active commit locks |
| `get_version_info` | PAN-OS version, serial, model |

API-key generation is intentionally **not** exposed as a tool. Generate the key once, out of band, with `curl` (see Step 0).

---

## Prerequisites

- **Podman 4.4 or newer** (`podman --version`). Podman 4.4 introduced the `--secret type=env` flag this guide depends on.
- On **macOS or Windows**, a running Podman machine (`podman machine init && podman machine start`). On Linux, Podman runs natively.
- **Palo Alto Networks Panorama** (PAN-OS 11.1 or newer)
- A Panorama admin account with a **read-only role** scoped as narrowly as your environment allows (see [Recommended Panorama Role](#recommended-panorama-role))
- A pre-generated **PAN-OS API key**

---

## Recommended Panorama Role

The server enforces read-only access at the application layer (only `<show>` operational commands and `action=show`/`action=get` config calls). However, an admin role with broad read access can still expose sensitive material such as **administrator password hashes** (`/config/mgt-config/users//phash`), **certificate private keys** (`/config/shared/certificate//private-key`), and shared secrets for RADIUS/TACACS/SNMP. The LLM can construct XPaths that target those nodes if RBAC permits it.

To minimize exposure:

1. Create a **custom Admin Role** under *Device > Admin Roles* (do not use the built-in "Superuser (readonly)").
2. On the **WebUI / XML API** tab, grant only:
   - XML API: Configuration (read), Operational Requests, Logs, Reports, Export
   - WebUI: read access scoped to the device groups, templates, objects, and policies you want Claude to see
3. Disable XML API access for: Commit, User-ID Agent.
4. Under *Configuration*, deny visibility into Mgt Config (admin users), Certificate Management, and any authentication/server profile nodes that contain shared secrets.
5. Set a finite **API key lifetime** under *Device > Setup > Management > Authentication Settings*.

---

## Step-by-Step Setup

### Step 0 — Generate Your Panorama API Key (out of band)

Run this from a trusted machine on a trusted network. Do **not** disable TLS verification when the admin password is on the wire.

```bash
curl -X POST 'https://<panorama-host>/api/?type=keygen' \
  --data-urlencode 'user=<admin-username>' \
  --data-urlencode 'password=<admin-password>'
```

If your Panorama uses a self-signed certificate, do this once instead of using `-k`:

```bash
echo | openssl s_client -connect <panorama-host>:443 -servername <panorama-host> 2>/dev/null \
  | openssl x509 > /tmp/panorama.pem

curl --cacert /tmp/panorama.pem -X POST 'https://<panorama-host>/api/?type=keygen' \
  --data-urlencode 'user=<admin-username>' \
  --data-urlencode 'password=<admin-password>'
```

You'll get a response like:

```xml
<response status="success">
  <result>
    <key>LUFRPT1xxxxxxxxxxxxxxxxxxxxxxxxxx==</key>
  </result>
</response>
```

Copy the `<key>` value — you'll use it in Step 4. Do not paste this key into chat with Claude.

### Step 1 — Get the Project Files

Make sure the `podman/` directory contains:

- `server.py`
- `Containerfile`
- `.containerignore`
- `requirements.txt`
- `.env.example` (template — copy to `.env` only if you use the plaintext Option B in Step 4; with the recommended Option A, secrets live in Podman)

`cd` into that directory before running the build.

### Step 2 — (macOS / Windows only) Start a Podman Machine

```bash
podman machine init
podman machine start
```

The Podman machine is a small VM that runs your containers. The image build, secret store, and `podman run` commands all operate inside it. Linux users skip this step.

### Step 3 — Build the Container Image

```bash
podman build -t panorama-readonly-mcp-server:latest .
```

Verify:

```bash
podman images | grep panorama-readonly
```

### Step 4 — Provide Secrets

You have two ways to give the container its credentials. **Option A (the Podman secret store) is strongly recommended** — secrets live in Podman's encrypted-on-disk store and only secret *names* appear in Claude Desktop's config. Option B (a plaintext `.env` file) is simpler but writes your API key to disk in clear text; use it only for quick local testing, or on Podman older than 4.4 (which lacks `--secret type=env`).

Regardless of which option you pick: use `PANORAMA_VERIFY_SSL=yes` whenever you can. Only set it to `no` if Panorama uses a self-signed certificate and you accept the risk; the safer alternative is to mount Panorama's CA cert into the container and keep verification on.

#### Option A — Podman secret store (recommended)

```bash
printf '%s' 'panorama.example.com' | podman secret create PANORAMA_HOST -
printf '%s' 'LUFRPT1xxxxxxxxxxxxxxxxxxxxxxxxxx==' | podman secret create PANORAMA_API_KEY -
printf '%s' 'yes' | podman secret create PANORAMA_VERIFY_SSL -
```

A few things to know:

- `printf '%s'` (without `\n`) avoids a trailing newline in the secret value. A stray newline in `PANORAMA_HOST` produces "Could not connect" errors that are tedious to debug.
- The values land in Podman's encrypted-on-disk secret store, which lives inside the Podman machine on macOS/Windows and under `~/.local/share/containers/storage/secrets/` on Linux.

Verify the secrets exist (values are not displayed):

```bash
podman secret ls
```

You should see `PANORAMA_HOST`, `PANORAMA_API_KEY`, and `PANORAMA_VERIFY_SSL`.

To rotate a secret later, remove it and recreate it:

```bash
podman secret rm PANORAMA_API_KEY
printf '%s' '<new-key>' | podman secret create PANORAMA_API_KEY -
```

Use the **Option A** config in Step 5.

#### Option B — Plaintext `.env` file (quick testing / Podman < 4.4)

> ⚠️ A `.env` file stores your API key in clear text on disk. Restrict its permissions (`chmod 600 .env`), never commit it (it's already covered by `.containerignore` and `.gitignore`), and prefer Option A for anything beyond local testing.

Create `.env` from the template and fill in real values:

```bash
cp .env.example .env
chmod 600 .env
# Edit .env and set PANORAMA_HOST, PANORAMA_API_KEY, PANORAMA_VERIFY_SSL
```

Use the **Option B** config in Step 5.

### Step 5 — Configure Claude Desktop

Edit your Claude Desktop configuration file:

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

Add the MCP server entry that matches the option you chose in Step 4.

**Option A — secret store:**

```json
{
  "mcpServers": {
    "panorama-readonly": {
      "command": "podman",
      "args": [
        "run",
        "-i",
        "--rm",
        "--secret", "PANORAMA_HOST,type=env",
        "--secret", "PANORAMA_API_KEY,type=env",
        "--secret", "PANORAMA_VERIFY_SSL,type=env",
        "panorama-readonly-mcp-server:latest"
      ]
    }
  }
}
```

What's important here:

- There is **no `env` block**. The Claude Desktop config only references secret **names** — the values stay in Podman.
- `--secret NAME,type=env` exposes the secret as an environment variable named `NAME` inside the container. Podman reads the value from its secret store at run time and never writes it to disk in plaintext.

**Option B — plaintext `.env` file:**

```json
{
  "mcpServers": {
    "panorama-readonly": {
      "command": "podman",
      "args": [
        "run",
        "-i",
        "--rm",
        "--env-file", "/absolute/path/to/.env",
        "panorama-readonly-mcp-server:latest"
      ]
    }
  }
}
```

Use the **absolute** path to your `.env` file. The values are read from that plaintext file at container start — keep it `chmod 600` and out of version control.

If `podman` isn't on Claude Desktop's `PATH` (common on macOS, where GUI apps don't inherit your shell's PATH), use the absolute path to the binary instead of `"podman"` — usually `/opt/homebrew/bin/podman` (Apple Silicon Homebrew) or `/usr/local/bin/podman` (Intel Homebrew). Run `which podman` in your shell to confirm.

### Step 6 — Restart Claude Desktop

Quit Claude Desktop fully and reopen it. The Panorama Read-Only server should appear in the MCP tools list.

### Step 7 — Verify

From your shell, run the same command Claude Desktop will run, but interactively:

```bash
podman run --rm -i \
  --secret PANORAMA_HOST,type=env \
  --secret PANORAMA_API_KEY,type=env \
  --secret PANORAMA_VERIFY_SSL,type=env \
  panorama-readonly-mcp-server:latest
```

It should start and wait on stdin for JSON-RPC. Press `Ctrl+C` to exit. If it fails, the error is shown on stderr — that's faster to diagnose than reading Claude Desktop logs.

In Claude Desktop, the tools menu should now include the Panorama tools, and a prompt like *"Show me all firewalls managed by Panorama"* should hit `list_managed_devices`.

---

## Using with Claude Code

Claude Code uses the same `command` / `args` schema as Claude Desktop, just in a different file. Three scopes:

| Scope | File | Sharing |
|---|---|---|
| **local** (default) | `~/.claude.json`, under this project's entry | just you, just this project |
| **project** | `.mcp.json` at the project root | shared via git with collaborators |
| **user** (global) | `~/.claude.json`, top level | just you, every project |

**Easiest path — let the CLI write it for you.** Pick the scope and option that matches Step 4:

Option A (Podman secret store, recommended):

```bash
claude mcp add -s user panorama-readonly -- \
  podman run -i --rm \
  --secret PANORAMA_HOST,type=env \
  --secret PANORAMA_API_KEY,type=env \
  --secret PANORAMA_VERIFY_SSL,type=env \
  panorama-readonly-mcp-server:latest
```

Option B (plaintext `.env` file):

```bash
claude mcp add -s user panorama-readonly -- \
  podman run -i --rm \
  --env-file /absolute/path/to/.env \
  panorama-readonly-mcp-server:latest
```

Use `-s user` for global, `-s project` to commit the entry to `.mcp.json` for collaborators, or omit `-s` for the default local scope. Verify with `claude mcp list`. If `podman` isn't on `PATH` when Claude Code launches, substitute the absolute path to the binary (same `which podman` advice as Step 5).

---

## Using with Codex

OpenAI Codex reads MCP server config from a TOML file instead of JSON. Two scopes:

| Scope | File | Trust requirement |
|---|---|---|
| **global** | `~/.codex/config.toml` | none |
| **project** | `.codex/config.toml` at the project root | Codex only loads project files for **trusted** projects — confirm trust in Codex before relying on this scope |

The translation from Claude Desktop's JSON is mechanical: `mcpServers.foo` → `[mcp_servers.foo]`; same `command`, same `args`.

Option A (Podman secret store):

```toml
[mcp_servers.panorama-readonly]
command = "podman"
args = [
  "run",
  "-i",
  "--rm",
  "--secret", "PANORAMA_HOST,type=env",
  "--secret", "PANORAMA_API_KEY,type=env",
  "--secret", "PANORAMA_VERIFY_SSL,type=env",
  "panorama-readonly-mcp-server:latest",
]
```

Option B (`.env` file):

```toml
[mcp_servers.panorama-readonly]
command = "podman"
args = [
  "run",
  "-i",
  "--rm",
  "--env-file",
  "/absolute/path/to/.env",
  "panorama-readonly-mcp-server:latest",
]
```

Restart Codex or open a new project thread so the MCP server loads. If `podman` isn't on Codex's `PATH`, substitute the absolute path in the `command` field.

---

## Usage Examples

Once connected, try these natural-language prompts in Claude:

- **"Show me all firewalls managed by Panorama"**
- **"What security rules are in the 'branch-offices' device group?"**
- **"Pull the last 50 threat logs from the past 24 hours"**
- **"Show me the running config for the firewall with serial 0123456789"**
- **"What's the HA status of Panorama?"**
- **"List all address objects in the shared location"**
- **"Get the top-applications report for the last 7 days"**
- **"Are there any uncommitted changes on Panorama?"**
- **"Run `show interface all` on firewall serial XYZ789"**
- **"What commit locks are active right now?"**

---

## Security Design

This server enforces read-only access at **three layers**:

### 1. Application Layer (code validation)

- `run_show_command` requires the command to start with `<show>` and rejects any payload that contains a blocked prefix: `<request>`, `<set>`, `<delete>`, `<debug>`, `<load>`, `<save>`, `<revert>`, `<schedule>`, `<test>`, `<clear>`, `<edit>`, `<configure>`, `<import>`, `<clone>`.
- `get_running_config` and `get_candidate_config` require the XPath to start with `/config` and limit length.
- All other config tools build their XPath from a fixed template; the only variable parts (device-group names, profile types, predefined object types) are validated against a whitelist of safe characters or against an enum of allowed values, blocking attribute-quote breakouts.
- No tool ever constructs `action=set`, `action=edit`, `action=delete`, `type=commit`, `type=import`, or `type=user-id` API calls.

### 2. API Call Layer (XML API only)

- All requests go to `https://<host>/api/` (the XML API endpoint).
- The REST API (`/restapi/`) is never used.
- Only allowed call patterns: `action=show`, `action=get`, `type=op` with `<show>` commands, `type=log`, `type=report`, `type=export` (config only), and `type=version`.

### 3. Panorama RBAC Layer (defense in depth)

- The admin role used for the API key should be a custom read-only role scoped per the [Recommended Panorama Role](#recommended-panorama-role) section.
- Even if a write call somehow slipped through, Panorama rejects it with error 15 (Operation denied) or 16 (Unauthorized).

### Additional security notes

- **Read-only is not the same as harmless.** A read-only role with broad config visibility can still leak password hashes, certificate private keys, and shared secrets. Use a custom role that hides those nodes.
- **Rotate the API key** periodically and set an API key lifetime on Panorama.
- **Never store the API key in Claude Desktop's config file.** Prefer the Podman secret store (`podman secret create`, Option A). If you use the plaintext `.env` file (Option B), `chmod 600` it and keep it out of version control — it holds your key in clear text.
- The container runs as a **non-root user** (UID 1000) inside the Podman container. Podman itself runs rootless by default.
- All logging goes to **stderr**, keeping stdout clean for the JSON-RPC protocol. Error messages returned to the LLM do not echo raw response bodies on authentication failures.

---

## Troubleshooting

### "Could not connect to Panorama"

- Verify `PANORAMA_HOST` is correct and reachable from inside the Podman machine. From your shell: `podman run --rm --secret PANORAMA_HOST,type=env panorama-readonly-mcp-server:latest sh -c 'echo $PANORAMA_HOST && getent hosts $PANORAMA_HOST'`
- Check that Panorama's management interface is accessible on HTTPS (port 443).
- Trailing newline in the secret value? Recreate it with `printf '%s'` (no `\n`).

### "HTTP 401" or "HTTP 403"

- The API key may be expired or invalid. Regenerate it (Step 0) and rotate the secret with `podman secret rm PANORAMA_API_KEY && printf '%s' '<new-key>' | podman secret create PANORAMA_API_KEY -`.
- The admin account may not have XML API access enabled. Check *Device > Admin Roles > XML API* on Panorama.

### "Failed to parse XML response from Panorama"

- This usually means Panorama returned non-XML (e.g., a captive portal or proxy interstitial). Confirm `PANORAMA_HOST` resolves to Panorama directly.

### "SSL certificate verify failed"

- For production, install a CA-signed cert on Panorama or mount Panorama's CA into the container so verification can stay on.
- For lab use only, recreate the secret as `no`: `podman secret rm PANORAMA_VERIFY_SSL && printf '%s' 'no' | podman secret create PANORAMA_VERIFY_SSL -`.

### "Bad XPath" errors

- Double-check the XPath syntax. The Panorama API browser at `https://<panorama>/api/` (logged in as your admin) is the easiest way to find valid paths.
- Device group names and object names are case-sensitive.
- The server rejects XPaths that don't start with `/config` and any name with characters outside `[A-Za-z0-9_.\- ]`.

### "Job did not complete within timeout"

- Log and report queries on large datasets can take time. The default timeout is 120 seconds.
- Narrow your query with a more specific filter or a shorter time range.

### Server doesn't appear in Claude Desktop

- Verify the image built successfully: `podman images | grep panorama-readonly`.
- Verify the secrets exist: `podman secret ls`.
- Confirm Claude Desktop can find `podman`. On macOS, replace `"podman"` in the config with the absolute path (e.g., `/opt/homebrew/bin/podman`).
- On macOS/Windows, confirm the Podman machine is running: `podman machine list`. If it shows `Currently running` is empty, run `podman machine start`.
- Restart Claude Desktop fully after any change.

### "unknown flag: --secret" or "type=env not supported"

- Your Podman is older than 4.4. Upgrade Podman, or use the plaintext `.env` path (Option B in Steps 4–5) — `--env-file` works on all Podman versions. Keep the `.env` file `chmod 600` and outside Claude Desktop's config directory.

---

## How to Add New Read-Only Tools

1. Add a new function in `server.py` following the pattern:

```python
@mcp.tool()
async def my_new_tool(param: str, target_serial: str = "") -> str:
    """Single-line description of what this tool does."""
    try:
        name = _validate_name(param, "param")
        root = await _panorama_request(
            {"type": "op", "cmd": f"<show><my><thing>{name}</thing></my></show>"},
            target_serial,
        )
        result = root.find(".//result") or root
        return f"Result:\n{_xml_to_text(result)}"
    except Exception as e:
        logger.error(f"Error in my_new_tool: {e}")
        return f"Error: {str(e)}"
```

2. Rebuild the image: `podman build -t panorama-readonly-mcp-server:latest .`
3. Restart Claude Desktop.

**Rules for new tools:**

- Only use `action=show`, `action=get`, `type=op` with `<show>` commands, `type=log`, `type=report`, `type=export`, or `type=version`.
- Never use `action=set/edit/delete/rename/clone/move/override`, `type=commit`, `type=import`, or `type=user-id`.
- Run any user-supplied value that ends up inside an XPath through `_validate_name()` or an enum check before interpolating.
- Single-line docstrings only.
- Default optional string params to `""`, never `None`.
- Always return strings.

---

## Architecture

```
Claude Desktop
   │
   │  spawns: podman run -i --rm --secret PANORAMA_HOST,type=env ...
   ▼
Podman (rootless)
   │
   │  reads PANORAMA_HOST / PANORAMA_API_KEY / PANORAMA_VERIFY_SSL
   │  from its secret store and injects them as environment variables
   ▼
panorama-readonly-mcp-server container
   │
   │  JSON-RPC over stdio with Claude Desktop
   │  HTTPS POST to https://<host>/api/
   ▼
Panorama XML API
```

Claude Desktop's config file contains only the `podman run` invocation and secret **names**. The actual credential values live in Podman's secret store and are injected at container start. They are never written into Claude Desktop's config file.

---

## License

This project is provided as-is for integrating Palo Alto Networks Panorama with Claude Desktop via MCP. Use at your own risk. Not affiliated with or endorsed by Palo Alto Networks.
