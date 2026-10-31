# Codex connection and verification

The Burp extension exposes a local Streamable HTTP MCP endpoint at
`http://127.0.0.1:9876/mcp`. Keep it bound to loopback and keep bearer-token
authentication enabled.

## Configure Codex

Codex reads MCP server entries from `%USERPROFILE%\.codex\config.toml`. Merge
this block into the file; if `[mcp_servers.burp]` already exists, update that
table instead of adding a duplicate:

```toml
[mcp_servers.burp]
url = "http://127.0.0.1:9876/mcp"
bearer_token_env_var = "BURP_MCP_TOKEN"
```

The environment variable must contain the bearer token currently shown in the
Burp MCP tab under **Security**. On Windows, open **Settings → System → About →
Advanced system settings → Environment Variables**, create or update the user
variable `BURP_MCP_TOKEN`, and paste the value locally. Do not put the token in
`config.toml`, a project file, terminal command history, or chat. If the
variable already exists but Codex receives HTTP 401, replace its value with
the current token shown by Burp; do not turn off authentication. Do not rotate
the Burp token unless the current one is unavailable or compromised.

After changing the variable, completely exit Codex and start it again so its
process receives the updated environment. Burp must also be running with the
MCP server enabled. Codex's CLI and IDE extension share the user MCP
configuration. See the [Codex MCP setup documentation](https://developers.openai.com/codex/mcp)
and [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).

## Check the connection

1. In Burp, confirm the Burp MCP tab says **Running** and shows
   `http://127.0.0.1:9876/mcp`.
2. In Codex's MCP server settings/status, confirm `burp` is connected.
3. Ask Codex to call `burp_get_status` and `burp_get_capabilities`. These are
   read-only checks and do not send traffic.
4. If the server is listed but authorization fails, verify the environment
   variable name and replace its value with the current Burp token locally.
   An unauthenticated request returning HTTP 401 is expected and confirms the
   listener is enforcing authentication; it does not indicate that the URL is
   wrong.

## Verify requests and responses safely

Use the [authorized loopback request procedure](../README.md#harmless-local-request-check)
to verify an ordinary HTTP request and response against the included local
test server. It requires explicitly adding `127.0.0.1:8000` to both Burp
Target scope and the MCP authorized-host allowlist, temporarily turning off
read-only mode, and approving the request in Burp.

For live interception, follow the [interception verification procedure](LIVE_INTERCEPTION.md#verification).
Use only a local target you control, authorize it in both Burp scope and the
extension allowlist, and approve each local Burp prompt yourself. The local
session has a hard maximum lifetime, automatically renews its short internal
lease, and stops on disable, expiry, or extension unload. Request/response
edits require exact-revision human approval before forwarding.

## Replace the extension JAR

Build `build\libs\burp-mcp-all.jar` using `build.ps1`, then in Burp open
**Extensions → Installed**, unload the old Burp MCP extension, and add the
replacement Java extension JAR. Do not clear Burp project data or reset the
extension's security settings. Confirm the endpoint and authentication state
in the Burp MCP tab, then update the local `BURP_MCP_TOKEN` value if the token
shown by the reloaded extension differs.
