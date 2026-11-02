# v1.5.0 milestone 1: exact target rule preparation

Development starts at verified v1.4.0 commit `73274b38a783e503ef7557086dfde40554f32cee`.
This milestone adds target-specific human authorization and disabled rule preparation.
It does not enable automatic execution for additional websites.

## Approval and bounds

`burp_request_target_rule_authorization` accepts 1–16 unique exact HTTP(S) URLs
on one lowercase host with an explicit port and a duration of 1–300 seconds.
Each URL must have a non-root path. Credentials, queries, fragments, wildcards,
encoded paths, duplicate slashes and dot traversal segments are rejected.
IPv6 and internationalized host names are not supported by this first milestone.

Every path must already be in Burp Target scope, and the existing MCP allowlist
must contain the exact `host:port` entry. Host-only and wildcard entries cannot
satisfy this check. The tool never changes either scope or allowlists.

Approval always uses the existing **Approve once / Deny** Burp dialog, including
the exact paths, duration and preparation-only limitation. Unattended localhost
mode cannot approve these grants. Denial, timeout or cancellation grants nothing.
Policy is rechecked after approval. Grants live only in memory, have a monotonic
deadline, and are not extended by use or status calls. A new grant always needs
another human approval. At most 16 grants can exist.

`burp_list_target_rule_authorizations` returns current grants. The ID can be used
as `authorizationReference` with the existing create/update rule tools. These
rules remain disabled. Expiry, observed scope/allowlist removal, read-only mode,
authentication disablement or session shutdown invalidates permission. Emergency
Stop also clears grants and invalidates pending approvals. Expired prepared rules
report `AUTHORIZATION_ENDED`; Emergency Stop keeps its existing latch and state.

The development MCP catalog has 88 tools, preserving all 86 existing tools.
Existing localhost rule execution, protected headers, credential filtering,
human disclosure approvals and emergency controls remain in place.

## Validation

Run development tests with isolated output:

```powershell
.\gradlew.bat -PdevelopmentBuild=true --no-configuration-cache test --tests '*TargetRuleAuthorizationTest' --tests '*LiveInterceptionTest' --tests '*InterceptionRuleEngineTest' --tests '*UnattendedLocalTestModeTest' --tests '*McpServerIntegrationTest' --tests '*BuildInfoTest' --console=plain
```

Tests use synthetic `.example` URLs and mocked approvals, clocks and Burp scope.
The MCP transport regressions use an embedded local server, not the running Burp
listener. No third-party traffic or live interception activation is required.
Outputs go to `build/dev-v1.5.0`; the stable release JAR is preserved.

## Remaining before external continuous execution

Bind grants to an explicitly approved live session and enforce the exact origin,
service identity, Host header, path and remaining authorization lifetime before
capture, evaluation and forwarding of every original and edited revision.
Then integrate credential-safe manual disclosure and forwarding decisions for
non-synthetic traffic, retaining the current fail-closed behavior and Emergency
Stop. External rules are deliberately rejected by the enable path until that
integration and its security tests are complete. v1.5.0 is not release-ready.

## Milestone validation result

The six listed test classes passed: 88 tests, zero failures, errors or skips.
The exact MCP catalog test confirms all 86 previous tools plus the two new tools.
The working and canonical v1.4.0 JAR SHA-256 values remain
`930ba28d126fe7b296ad61ecd4bab830044dfc07bccb1dee484cd72a35dbe8c2`.
