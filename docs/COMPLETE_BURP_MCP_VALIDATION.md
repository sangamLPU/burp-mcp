# Complete Burp MCP Validation

**Date:** 2026-11-01
**Repository:** D:\Projects\MCP
**Branch/base:** main / 57cf38165bb2e3e1f26f3867b2d4a9c2f21beeb8 before this validation cycle
**Running build:** 20261101.5-burp2024.1.1.1
**Burp:** Professional 2024.1.1.1-26891
**Extension version:** 1.3.2
**Montoya compile baseline:** 2023.12.1
**Primary artifact:** build/libs/burp-mcp-all.jar

## Executive summary

The loaded extension is responsive and authenticated MCP calls succeeded. The runtime reports build .5, version 1.3.2, Burp Professional, bearer authentication required, and a running listener at http://127.0.0.1:9876/mcp. The current connector catalog contains **71 tools**. Seven read-only runtime tools were invoked successfully during this verification; the remaining entries have registration and input-signature evidence only.

The nine fixed http://127.0.0.1:8000 paths all report inBurpScope=true, hostAllowlisted=true, and eligible=true. The current live state is safe for continued offline work: interception is disabled, the session and heartbeat are expired, unattended mode is inactive, and both pending queues are empty.

The latest LOCAL run completed **21 PASS, 0 FAIL, 0 BLOCKED, 0 INCONCLUSIVE, 2 UNVERIFIED, 0 UNSUPPORTED**. The wrapper correctly classifies its aggregate as **INCONCLUSIVE** because approval-gated live behavior and candidate JAR creation remain unverified. Its Gradle task was up-to-date in that coordinator run; a subsequent forced execution ran **182 JUnit tests, 0 failures/errors/skips**. No live cancellation request was sent. **Phase 4A remains INCONCLUSIVE** pending active human-enabled authorization and actual Burp drop evidence.

The packaged JAR was not rebuilt or replaced. Its SHA-256 remained 75186ec81d6f9d16c19802368677d4b33d1294d62e020cf338ccc3da5103b1d4. The coordinator now excludes shadowJar by default; candidate packaging requires an explicit -BuildCandidate.

Machine-readable results:
- [Latest LOCAL coordinator report](../build/reports/full-validation/validation-f3caf344080f419789e343edcb8d8bb6.json)
- [Latest OFFLINE coordinator report](../build/reports/full-validation/validation-29830fabd6a748e490fc9d2aa79f29c1.json)
- [Latest SUPERVISED preflight report](../build/reports/supervised-reliability-20261101T072516Z-8740b7cd.json)
- [OFFLINE coordinator report](../build/reports/full-validation/validation-6abf0e7fb826423ea699ea968b6f6aa1.json)
- [71-tool catalog and input signatures](../build/reports/tool-catalog-audit.json)
- [Mission summary JSON](../build/reports/burp-mcp-validation-summary.json)

## Current runtime evidence

| Check | Result | Evidence |
|---|---|---|
| MCP connection | PASS, live | burp_check_connection returned connected/running at the expected loopback endpoint and Burp version. |
| MCP authentication | PASS, live | The endpoint reports bearer authentication required; authenticated read-only MCP calls succeeded. No token was displayed or written. |
| Runtime build | PASS, live | burp_get_status and burp_get_capabilities both report 20261101.5-burp2024.1.1.1. |
| Tool catalog | PASS, registration/schema | Connector metadata has 71 entries, matching expectation. Seven read-only calls were executed; 64 were not executed individually. |
| Burp version | PASS, live | Burp Suite Professional 2024.1.1.1-26891. |
| Scope and allowlist | PASS, live | All nine exact localhost URLs returned eligible. This is a URL eligibility check; Montoya does not expose a full enumerable scope ruleset here. |
| Live interception | OFF | enabled=false; sessionEndReason=SESSION_EXPIRED; heartbeat is EXPIRED because there is no active session. |
| Unattended Local Test Mode | OFF | active=false, no current identities, remaining time zero. It was not activated by this validation. |
| Pending request queue | PASS, live | Empty. |
| Pending response queue | PASS, live | Empty. |
| Run ID/server identity copy controls | PASS, component tests; GUI UNVERIFIED | JUnit covers presence, read-only Run ID, masked server identity, current-state recheck, secure copy commands, and conditional clipboard cleanup. `cua.getState()` and `cua.listWindows()` failed with the native-pipe-unavailable error after a clean reconnect; the helper process and a matching pipe are visible locally, but the supported API cannot connect. No control was clicked or clipboard changed. |
| Local fixture | PASS, local | The bounded fixture and identity-enforcement regressions passed; port 8000 was released after testing. |
| MCP responsiveness | PASS now; freeze unresolved | Live read-only calls returned successfully. Local integration tests passed eight cases, including eight concurrent status calls while a mock approval was pending. The historical service-wide freeze was not reproduced and its root cause is still unknown. |

The seven live-verification tool calls were burp_check_connection, burp_get_status, burp_get_capabilities, burp_get_intercept_status, burp_list_pending_requests, burp_list_pending_responses, and burp_get_scope.

## Test results

### Full LOCAL validation

Coordinator run ID: f3caf344080f419789e343edcb8d8bb6.

- 21 coordinator checks passed; no coordinator failures or blocked items. The wrapper aggregate is INCONCLUSIVE because two checks remain unverified.
- Two items remain UNVERIFIED by design: approval-gated live Burp behavior and creation of a new candidate JAR.
- This LOCAL coordinator run completed in 52.81 seconds with 21 PASS, 0 FAIL, 0 BLOCKED, 0 INCONCLUSIVE, and 2 UNVERIFIED. A forced Gradle execution in the same validation cycle passed 182 JUnit tests, with no failures, errors, or skipped tests. The direct command excluded shadowJar and did not rebuild the JAR.
- The JUnit set includes eight local MCP integration tests: bearer rejection, tool listing, input validation, safe disclosure behavior, pending approval serialization, graceful shutdown, and concurrent status responsiveness.
- The server fixture reported 23 local cases passed; the separate identity-enforcement script exited successfully.
- JAR packaging was excluded. Existing manifest identity and SHA-256 were checked read-only.

### Offline cancellation and authentication regressions

- Cancellation preflight policy/coordinator API: **31 Python tests passed**, including the 150-second cancellation budget, independently expiring session and authorization deadlines, active identity retrieval, nine-target scope, one-shot drop evidence, and stale-ID operations.
- Setup authorization budget: setup requires **180 seconds** remaining: the 150-second request budget plus 30 seconds for the required Burp-local session activation. Values at 300, 240, and 180 pass; 150 and 120 fail before session activation.
- Authentication transport: **14 Python tests passed**.
- PowerShell auth/process handling: **38 assertions passed**, including secure prompt fallback after HTTP 401, missing/rejected tokens, stderr/nonzero child exit, zero/one/multiple Python arguments, and captured identity handoff without console output.
- Copied workflow simulation: **26 assertions passed**. A controlled child process exercised fixture readiness, setup preflight before pause, pause/resume, final preflight, setup/final failures, and the no-request gate. It contacted no Burp or origin server.
- Supervised coordinator simulation: **22 assertions passed** in actual PowerShell child processes. It exercised identity capture, fixture lifecycle, setup-before-session ordering, a single runner and drop, cleanup, setup-failure gating, inactive-authorization blocking, and aggregate status propagation; no Burp or HTTP request was sent.
- Identity-bound fixture handoff: **10 local assertions passed** using the real prepare script and server. It verified process-environment identities, a matching direct health response, no identity/token values in process arguments or result output, and cleanup of only the fixture's listener.
- Cancellation response validator: **19 framing/outcome cases passed**; NetworkRequestsSent=0.
- Concurrent runner validator: positive edited framing, malformed framing rejection, and cross-association rejection passed; NetworkRequestsSent=0.
- PowerShell syntax checks and git diff --check passed.
- Full OFFLINE coordinator: **18 PASS, 0 FAIL, 3 BLOCKED, 2 UNVERIFIED**; the aggregate is BLOCKED. The three blocked items are the local-only suites deliberately excluded by OFFLINE mode.

## Reliability fixes verified offline

1. A structurally valid but rejected environment token now triggers a secure prompt fallback under -PromptForMcpToken. The token remains in process memory, is not printed, and is not placed on a command line or persisted. A bad prompted token produces a clear, non-secret failure.
2. PreflightArguments @() is accepted with AllowEmptyCollection; Python receives no additional arguments for the final preflight.
3. The final request budget is derived from the 125-second client observation deadline plus 25 seconds of safety margin, yielding 150 seconds. Both interception-session and unattended-authorization remaining time are checked independently.
4. The copied workflow now runs authenticated setup, identity, scope, queue, and fixture checks before the user activates interception. After that single human action, it pauses once, performs one fast final preflight, and sends at most one request. Any preflight failure prevents test traffic.
5. run-full-validation.ps1 no longer overwrites the packaged JAR by default. The Gradle test task depends on shadowJar, so normal validation adds -x shadowJar. A candidate build requires explicit -BuildCandidate; backup, packaging, and candidate copy are then intentional.
6. Deadline tests and runner tests keep both session and unattended authorization expiry distinct. The runner never retries an ambiguous request.
7. The new `run-supervised-reliability-suite.ps1` keeps OFFLINE, LOCAL, and SUPERVISED modes distinct. In SUPERVISED mode it reads identities through authenticated MCP into process memory, verifies all nine targets, starts the fixture, passes setup preflight, asks the existing unattended policy for one 180-second session, then runs one request/drop and verifies cleanup. It never activates unattended mode or retries traffic.
8. Direct runtime testing found that `initialize()` required a client argument even though production preflight entry points called it without one. It now creates the default MCP client when omitted; direct construction and injection both have regressions. Unexpected errors are returned as bounded, non-secret preflight failures rather than tracebacks.

Detailed root causes and fixes are in [BURP_MCP_BUG_FIX_LOG.md](BURP_MCP_BUG_FIX_LOG.md).

## Phase status and coverage matrix

Statuses below distinguish direct current evidence from historical results and offline/mock coverage. Historical live results were not rerun in this mission.

| Area | Level | Status | Evidence / limitation |
|---|---|---|---|
| MCP connectivity | Live | PASS | Current connection and status tools succeeded. |
| Authentication | Live + offline | PASS | Bearer required; authenticated MCP preflight succeeded; 14 transport tests and 38 PowerShell assertions passed. |
| Tool registration | Live catalog | PASS | 71 connector entries. |
| Tool schemas | Catalog metadata | PASS | All 71 entries include a callable signature and required/optional argument extraction. |
| All 71 tool behaviors | Per-tool | PARTIAL | Seven read-only calls live-verified; 64 are registration/schema verified only. See catalog JSON; no blanket functionality claim. |
| Burp scope | Live | PASS | All nine fixed localhost URLs eligible. |
| Target allowlist | Live | PASS | Same nine exact URLs all allowlisted. |
| Local scope helper | Live state change | UNVERIFIED | Not invoked because the existing targets already qualify and its local approval is required. |
| Unattended policy | Unit/local identity | PASS offline/local | Exact paths, host/port, identities, limits, expiry, and manual activation are covered by tests. Live mode remains off. |
| Automatic approvals | Live | UNVERIFIED | No live automatic decision was made; authorization is currently inactive. |
| Manual approval serialization | Local mock | PASS | Pending mock approval did not block eight status calls. No live human prompt was triggered. |
| Phase 4A request cancellation | Live | INCONCLUSIVE | No /test-cancel request was sent. Actual capture, approval source, drop, origin zero-delivery, client result, stale ID, and cleanup still require supervised evidence. |
| Phase 4A preflight and client classifier | Offline | PASS | Deadline, authentication, byte framing, terminal outcome, wrong ID, duplicate delivery, and no-traffic tests passed. |
| Supervised coordinator | Offline simulation + live read-only preflight | PARTIAL | 22 actual PowerShell child-process assertions passed. Live preflight confirmed the mode is inactive and stopped before fixture/session; no request was sent. |
| Phase 4B message timeout | Offline state machine | PASS | Expiry, fail-closed callback behavior, stale decision rejection, and queue cleanup covered. Live timeout remains UNVERIFIED. |
| Phase 4C session expiry/disable/emergency stop | Offline state machine | PASS | Expiry, disable, emergency cancellation, heartbeat cleanup, and callback release covered. Live variants remain UNVERIFIED. |
| Phase 4D queue capacity and concurrency | Offline state machine | PASS | Deterministic 1/2/4/8 message isolation and capacity tests passed. Live unattended mode remains limited to two in-flight messages; larger live tests are not authorized. |
| Approval serialization/BUSY | Offline + historical live | PARTIAL | Serialization and responsiveness pass locally; prior BUSY behavior was consistent with one-at-a-time prompts. No live repeat. |
| Stale IDs and revisions | Offline | PASS | Stale revisions, invalidated approvals, and terminal IDs are rejected by tests. Live stale-ID test pending. |
| Duplicate forwarding | Offline | PASS | Competing terminal decisions complete once; live repeat not run. |
| GET / POST / PUT / PATCH / DELETE request handling | Local fixture + historical live | PARTIAL | Local fixture validates methods; prior supervised GET/POST interception passed historically. Current Burp interception was not enabled. |
| Query/path/header editing | Historical live + offline | PARTIAL | Earlier live header/path/body workflows are documented; not rerun here. |
| JSON and nested JSON | Historical live + unit/local | PARTIAL | JSON request modifications passed historically; this mission did not send through Burp. |
| URL-encoded forms | Local fixture + historical live | PARTIAL | Fixture and historical form edit evidence exists; no live repeat. |
| Multipart and file uploads | Local fixture + historical live | PARTIAL | Bounded local multipart/file integrity passed; previous 41-byte live upload and SHA-256 result is historical only. |
| Request cookies | Historical live | PARTIAL | Earlier synthetic cookie editing passed; not rerun. Current auth/cookie analysis is redacting. |
| Response headers and Set-Cookie | Historical live + local tests | PARTIAL | Prior live header/cookie edits passed; not rerun. |
| HTML response editing/browser rendering | Historical live | PARTIAL | Prior modified HTML rendered in Burp browser; not rerun. |
| Response-body modification | Offline/mock + historical live | PARTIAL | Callback patch/drop unit tests pass; historical HTML/JSON edits are not rerun. |
| Content-Length | Local + offline + historical live | PARTIAL | Local fixture, parser, and historical modified-body checks pass; no live current-run framing test. |
| Chunked transfer | Fixture limitation | UNSUPPORTED by fixture | The local fixture explicitly rejects chunked request framing; extension-through-Burp behavior remains UNVERIFIED. |
| Binary integrity | Local fixture | PASS | Synthetic binary byte integrity was verified locally. |
| Unicode | Local fixture | PASS | UTF-8 body byte count/identity validated locally. |
| Duplicate delivery / request-response association | Offline + historical live | PARTIAL | Queue isolation tests pass; previous two-request live association result is historical. |
| HTTPS/TLS | None | UNVERIFIED | No localhost certificate fixture or trust changes were used. |
| HTTP/2 | Capability/tool surface | PARTIAL | Burp reports HTTP/2 request capabilities and tools; interception/editing over HTTP/2 was not tested. |
| gzip/deflate/Brotli | Source + no live fixture | PARTIAL | Body replacement on non-identity Content-Encoding is explicitly rejected; pass-through integrity and decompression were not tested. |
| Streaming/SSE through proxy | Source/capability | UNVERIFIED | No streaming interception test; MCP streamable HTTP transport support is separate from proxied streaming. |
| WebSockets | Source inspection | PARTIAL | A ProxyWebSocketMessage serializer exists, but WebSocket history is deliberately not exposed because connection metadata is insufficient for scope enforcement; frame interception was not tested. |
| HTTP/3 | Source/capability | UNSUPPORTED | No HTTP/3 capability or tool is exposed by this Burp/Montoya integration. |
| Extension shutdown/recovery | Local mock | PASS partial | MCP integration shutdown test passed; Burp extension unload/reload was not performed. |
| MCP responsiveness/freeze | Live + mock | INCONCLUSIVE | Current server responsive; local concurrency tests passed; historical service-wide freeze has no confirmed root cause or fix. |
| Repeated-session/soak testing | None | UNVERIFIED | No soak test was run in this turn. |

## Protocol and compatibility notes

The capability endpoint reports Montoya baseline 2023.12.1, HTTP/1 and HTTP/2 request operations, Professional scanner findings, passive audit, Repeater send, and Collaborator support. It reports no Repeater tab enumeration and disables active audit because legacy checks can be intrusive.

Build metadata says 1.3.2 / 20261101.5-burp2024.1.1.1; the JAR was built with JDK 18 and the project targets Java 17 bytecode. The exact loaded Burp version is confirmed. The packaged artifact was not modified during validation. HTTPS/TLS, HTTP/2 interception, compression, streaming, and long-lived protocols remain unverified or unsupported as marked above.

## Artifact, backup, and repository state

- Existing JAR SHA-256: 75186ec81d6f9d16c19802368677d4b33d1294d62e020cf338ccc3da5103b1d4.
- Existing preserved artifacts include the versioned .1 through .4 JARs and hash-named backups. The current .5 JAR remains in place.
- No JAR rebuild occurred in this validation. No Burp reload is needed because no packaged artifact was changed.
- This report records the pre-commit validation state. The reviewed source, test, and documentation changes are committed locally at handoff. No secrets or private identities were included, and no push has occurred.
- Candidate is suitable to keep for supervised testing, but **not ready to push or claim release-ready** until Phase 4A has live evidence and the remaining supervised protocol/reliability limitations are recorded.

## Minimum remaining actions

1. The supported desktop-control API currently cannot connect to its native pipe, so GUI automation is blocked. A human must enable Unattended Local Test Mode in Burp; no attempt was made to bypass that UI requirement.
2. After the mode is active, run or authorize the coordinator command `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/run-supervised-reliability-suite.ps1 -Mode SUPERVISED`. It handles identity, fixture, session, one-shot traffic, policy drop, and verification. If Burp presents a confirmation that requires a physically present human, that confirmation must be handled locally.
3. The latest SUPERVISED attempt authenticated and stopped before fixture/session startup because unattended mode was inactive. It sent no request. Phase 4A stays INCONCLUSIVE until every live evidence item passes.
4. Continue live 4B/4C/4D only while the current explicit authorization remains valid and their individual preconditions pass; otherwise retain their offline results and mark live behavior UNVERIFIED.
