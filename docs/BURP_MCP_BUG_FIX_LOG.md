# Burp MCP Bug Fix Log

**Updated:** 2026-11-01
**Runtime under validation:** 20261101.5-burp2024.1.1.1

## Confirmed defects and repairs

| ID | Root cause | Repair | Regression evidence | Runtime effect |
|---|---|---|---|---|
| BF-01 | The authentication prompt fallback treated a missing or malformed token as recoverable, but a valid-shaped environment token rejected with HTTP 401 entered the ordinary nonzero-child failure path. PowerShell surfaced stderr as NativeCommandError, obscuring the intended retry decision; ErrorActionPreference was a reporting symptom, not the missing fallback condition. | The runner captures stdout/stderr and exit code separately, classifies 401 as rejected authentication, securely prompts once for a fresh token, retries only the read-only preflight, redacts the token, and returns a non-secret error if the new token fails. | 14 Python transport tests; 36 PowerShell process/auth assertions, including HTTP 401 fallback, stderr, nonzero exit, no token output, and process environment restoration. Authenticated live MCP calls also succeeded with the extension requiring bearer auth. | No authentication weakening or embedded credential. |
| BF-02 | Mandatory PowerShell string-array binding rejected an empty PreflightArguments collection before the helper could start Python. | Added AllowEmptyCollection to the argument parameter and preserved an empty argv tail, so Python receives only the script path for the final preflight. | 36 PowerShell assertions cover zero, one, and multiple arguments using a controlled child. | No live request involved. |
| BF-03 | The 240-second threshold was unrelated to the actual bounded exchange and caused safe requests to be rejected after manual setup. | Final-session minimum is max(120s intercepted hold, 125s client observation) + 25s safety = 150s. Both session and unattended-authorization clocks are checked independently. The pre-session setup check requires 180s of authorization: the same 150s test budget plus 30s for the required human Burp activation. | 20 Python policy tests check both final deadlines at 300/240/180/150/120 seconds and the setup budget at the same boundaries. | The 150s check is still a gate; no request is sent if either final clock is insufficient. |
| BF-04 | The copied runner paused for live interception before it authenticated, checked scope, and verified the identity-bound fixture. A setup problem could therefore consume the session window. | With the copied workflow's WaitForLiveSession option, the runner now performs one setup-only authenticated preflight before pausing. After the human activates a fresh session, it performs one final preflight and then sends at most one request. Setup or final preflight failure prevents all test traffic. | 26 offline copied-workflow assertions exercise fixture -> setup -> pause -> resume -> full preflight, setup failure and final failure, with a controlled child and no Burp/origin traffic. The Python setup path has an additional one-snapshot regression. | The workflow still requires the user to activate unattended authorization and live interception in Burp. It does not auto-enable or renew either. |
| BF-05 | Gradle's test task depends on shadowJar and replaced build/libs/burp-mcp-all.jar during ordinary validation. | Full validation now excludes shadowJar by default and verifies the existing JAR read-only. Candidate packaging, backup, and candidate copy require the explicit -BuildCandidate switch. | Five orchestrator assertions verify default exclusion and explicit opt-in. Full OFFLINE and LOCAL runs passed with packaging excluded; artifact SHA-256 stayed unchanged. | No JAR rebuild in this mission. |
| BF-06 | Client cancellation-response parsing needed stricter byte/framing handling and identity/delivery predicates. | The existing validator rejects incomplete or conflicting framing, unexpected success, wrong identity, and duplicate delivery; the final runner has a bounded 125s read and no retry. | 19 PowerShell validator cases passed with NetworkRequestsSent=0; live cancellation remains unperformed. | Phase 4A remains INCONCLUSIVE. |

## Responsiveness finding

The historical audit reproduced a service-wide MCP stall while TCP listeners remained open and captured a JVM dump with 99 threads, without a deadlock marker. It did not prove executor starvation, approval blocking, or a specific lock cause. During this verification the loaded MCP server answered live read-only calls, and the LOCAL suite passed eight MCP integration tests, including eight concurrent status requests during one mocked pending approval. The historical freeze was not reproduced; it is **unresolved**, not fixed.

Source review confirms Ktor/Netty handles MCP requests; KtorServerManager's single-thread executor serializes server lifecycle start/stop work. DecisionQueue waits without holding its synchronized lock and are bounded by the message deadline. These findings do not establish why the historical service-wide freeze occurred.

## No extension-side defect requiring a JAR rebuild

The defects fixed in this validation cycle are in Python/PowerShell preflight/orchestration and the Gradle validation coordinator. The current .5 runtime matches gradle.properties and the existing JAR manifest. No JAR was rebuilt, and no Burp reload is required for these script-only repairs.

The source changes already present for the .5 UI controls and unattended-policy behavior passed the 182-case JUnit LOCAL suite. They are not claimed as a fresh runtime deployment beyond the loaded .5 build evidence.

## Validation references

- Latest full LOCAL report: ../build/reports/full-validation/validation-2caae7264ab443aaba138fbf4f147a73.json
- Full OFFLINE report: ../build/reports/full-validation/validation-6abf0e7fb826423ea699ea968b6f6aa1.json
- Tool catalog audit: ../build/reports/tool-catalog-audit.json
- Full coverage matrix: COMPLETE_BURP_MCP_VALIDATION.md
