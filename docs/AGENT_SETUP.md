# Burp MCP agent setup and operation

This runbook supports a fresh Windows restart or private clone without relying
on a previous chat. Development is paused at **1.5.0-dev.6**, build
**20261107.3-scanner-permission-hardening-dev**. Features are frozen. Read
[development status](DEVELOPMENT_STATUS.md) before taking action. No command or
plan below authorizes application traffic or a supervised test.

## Locate the project and recover state

The existing workspace is `D:\Projects\MCP`, branch `dev/v1.5.0`. A fresh clone
may use another directory; run commands from its root. For a new checkout only:

```powershell
git clone --branch dev/v1.5.0 https://github.com/sangamLPU/burp-mcp.git
Set-Location .\burp-mcp
git status --short
git branch -vv
git log -5 --oneline
```

The checkpoint must first be pushed by the owner before it can appear in a fresh
remote clone. Until then, preserve this local Git repository as well as its ignored
evidence. Never reset, clean or switch a dirty workspace to obtain this state.
Read `AGENTS.md`, `gradle.properties`, and `src/main/kotlin/net/portswigger/mcp/BuildInfo.kt`.
Require agreement on version/build. Main/v1.4.0 is the verified rollback baseline.

## Dependencies and isolated build

Use Windows PowerShell 5.1 or newer, Git, Python 3.10 or newer, a Java 17 JDK,
and Burp Suite Professional **2024.1.1.1**. Montoya compile baseline is 2023.12.1;
extension bytecode targets Java 17. Gradle wrapper 9.2.0 pins the build. A first
build needs access to Gradle/Maven dependency downloads. Python coordinators use
the standard library. No model gateway is required by the extension.

```powershell
java -version
python --version
.\gradlew.bat -PdevelopmentBuild=true --no-configuration-cache test shadowJar --console=plain
```

Output: `build\dev-v1.5.0\libs\burp-mcp-1.5.0-dev.6-all.jar`. Preserve an existing
same-version artifact before rebuilding: packaging includes build metadata, so a
fresh build need not have the recorded binary hash. Do not use `build.ps1`,
default-output `clean`, or default-output packaging against the preserved release
workspace. Never silently replace a loaded extension.

The qualified local dev.6 JAR has SHA-256
`2dc9a09331397f3cf7dddf0b9bf6f9460d26eb9a5e3742c322b7fa07ee6859dc`.
It is ignored and is not supplied by a source clone. Verify locally:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\build\dev-v1.5.0\libs\burp-mcp-1.5.0-dev.6-all.jar'
```

For fast checks against that already matching JAR, without repackaging:

```powershell
.\gradlew.bat -PdevelopmentBuild=true -x shadowJar --no-configuration-cache test --tests '*BuildInfoTest' --tests '*McpServerIntegrationTest.scanner listing permission*' --console=plain
python -B -m unittest discover -s scripts -p 'test_live_rule_engine_coordinator.py'
powershell -NoProfile -File .\scripts\test-phase2-method-fixture.ps1
git diff --check
```

`-x shadowJar` requires the existing matching package; omit that exclusion on a
fresh build. `--offline` is optional only after dependencies are cached. These
tests use mocks/local MCP transport and the pure fixture builder; they do not
send application traffic through the running Burp instance.

## Load the extension and connect

The human opens the intended Burp project. Before any unload/reload, inspect held
messages and active authority; unloading may resolve held traffic. In Extensions
> Installed, unload the old MCP instance and add the intended Java JAR. Confirm
exactly one MCP extension is Loaded, its actual path, manifest version/Build-Id
and SHA-256. A filename alone is insufficient. Keep the stable JAR for rollback.

Burp MCP > Server Settings should report Running at
`http://127.0.0.1:9876/mcp`. The transport is Streamable HTTP; dev.6 requires
loopback binding and bearer authentication. Human-managed security controls live
under Burp MCP > Security. Keep project-data and HTTP-request approval required,
credential filtering enabled and persistent Always Allow exceptions disabled
for permission testing. Do not change native permissions to make a check pass.

Configure an MCP client to send `Authorization: Bearer` using the current local
token as an environment-backed secret. Do not paste the value into chat, source,
logs or committed configuration. The human can populate a process-only variable:

```powershell
$env:BURP_MCP_TOKEN = [System.Net.NetworkCredential]::new(
    '', (Read-Host 'Current Burp MCP token' -AsSecureString)
).Password
```

For Codex, merge into `%USERPROFILE%\.codex\config.toml`, avoiding duplicate tables:

```toml
[mcp_servers.burp]
url = "http://127.0.0.1:9876/mcp"
bearer_token_env_var = "BURP_MCP_TOKEN"
```

Launch the client from that environment and check `/mcp`. The environment-backed
HTTP configuration is documented in the
[official MCP guide](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).
[Codex setup](CODEX_SETUP.md) describes credential diagnosis. A new project may
have another token. HTTP 401 requires checking the actual credential, not disabling
authentication. Do not restart a shared daemon during active work; diagnose first.
Client registration/listing alone is not proof of an authenticated live connection.
Remove the shell variable after use with `Remove-Item Env:BURP_MCP_TOKEN`.

## Safe initial inspection and preflight

Initialize MCP, list tools and require **89 unique names** on the supported
Professional runtime. Read `burp_get_status`, `burp_check_connection`,
`burp_get_capabilities`, `burp_get_intercept_status`,
`burp_list_target_rule_authorizations`, `burp_list_interception_rules`,
`burp_get_rule_engine_status`, and both pending-message lists. Use `burp_get_scope`
only to evaluate known URLs; it neither enumerates scope rules nor sends requests.
These administrative checks do not authorize protected project-data access.

Require managed interception off, unattended inactive, zero remaining session/lease,
empty queues/grants/rules, Emergency Stop clear and fixture stopped. Confirm
native Proxy Intercept OFF separately. Keep the existing Proxy listener on 8080.
Inspect the human-selected project and actual native security settings separately;
the API cannot establish every UI setting or identify the project on this API baseline.

The original basic-mode HTTP scope prefixes on `127.0.0.1:8000` are:
`/test-html`, `/test-post`, `/test-form`, `/test-upload`, `/test-cancel`,
`/test-timeout`, `/test-session-expiry`, `/test-concurrent-a`, `/test-concurrent-b`.
Each is enabled with subdomains disabled. The sole MCP host entry is
`127.0.0.1:8000`. Root and unrelated paths must remain excluded. Do not expand
scope, add duplicates or overwrite unrelated settings. A fresh project needs
separately reviewed human configuration; source checkout does not restore it.

With the existing approved configuration, the only Phase 2 preflight CLI is:

```powershell
python -B scripts/live_rule_engine_coordinator.py --target-preflight-only
```

It performs authenticated MCP/static eligibility checks and a Proxy TCP availability
check; it does not start a fixture, grant, rule, session, scan or application request.
It expects write mode/live edits configured for the later test but does not enable
them. A failure is a blocker, not permission to change settings. Native Proxy state
and project identity still require separate observation. **Never invoke this
coordinator without the flag as a preflight:** its no-argument runner sends the
legacy nine-exchange workflow.

## Authorized rules and fixture operation

Read [target authorization](V1_5_0_TARGET_AUTHORIZATION.md),
[rule engine](INTERCEPTION_RULE_ENGINE.md), and
[Phase 2 plan](PHASE2_TARGET_SESSION_PLAN.md). The last approved Batch A target was
`http://127.0.0.1:8000/test-post-phase2`, POST, three attempts maximum. That approval
is consumed. Do not repeat it or reuse its grants, IDs or evidence directory.

For a future separately authorized target window, request
`burp_request_target_rule_authorization(urls, durationSeconds)` and wait for the
human's native Approve once. The grant permits disabled rule preparation only.
Use its returned ID as `spec.authorizationReference` in
`burp_create_interception_rule(spec)`. Capture returned rule IDs and full immutable
specifications. Then request `burp_start_target_rule_session(grantId, ruleIds,
durationSeconds)` and wait for a second human approval. Recheck the actual grant,
session, rules, revisions, lifetime, scope and queues before each attempt. Numeric
rule revisions are internal; retain specification hashes rather than inventing them.

Supported transformations: JSON field set/remove, query/form parameter set/remove,
request/response header set/remove, literal UTF-8 text replacement. Routing,
framing and credential headers are protected. Target sessions reject DROP.
Rule budgets, TTL and native approval never increase the authorized client-attempt cap.
Unattended Local Test Mode is separate and must remain inactive for these batches.

Only after separate fixture/traffic approval, start `scripts/local-test-server.ps1`
with `-RuleEngineTestMode`, a unique ignored `-LogPath`, and approved
`-MaxRequests`/`-MaxRunSeconds` limits. Use no unattended identities for Phase 2.
Verify script hash, PID and loopback port ownership first; occupied port means stop.
Do not add an HTTP health probe unless separately counted and authorized. The
fixture's `-MaxRequests` counts origin deliveries, not client attempts. Existing
target helpers supply one-shot transport, readiness and evidence checks; their
construction supplies no execution authority. No generic C-H live runner is approved.

## Evidence cleanup and resumption

Record each attempt durably before sending, with unique synthetic case IDs. Compare
client results against independent origin observations, request/response hashes,
framing and rule counters. Tool success alone is insufficient. Stop on an unexpected
prompt, data, destination, revision, count, timeout or unresolved worker. No retries,
redirect following, silent renewal or permission bypass.

For cleanup, stop new attempts, resolve bounded clients, inspect queues, pause only
owned rules, stop the owned session through its native approval or observe expiry,
verify grants/session inactive, delete only owned rules and stop only the owned
fixture PID. Held messages retain their existing human decision/deadline path.
Do not use Emergency Stop as routine cleanup: it drops held traffic and latches
rules off. Do not clear unrelated configuration or evidence. Require final safe
state and preserved scope/allowlist before closing a batch.

Local evidence under `build/reports/` is not in Git. Keep a private backup of this
directory and stable/development JARs separately. Never execute historical report
scripts against frozen bundles; some overwrite evidence. The portable
[development status](DEVELOPMENT_STATUS.md) and
[remaining campaign](SUPERVISED_CAMPAIGN.md) preserve conclusions and next steps.
First resolve the already completed denial attempt's category/human-decision
attribution; no new protected-data call is authorized by this runbook.
