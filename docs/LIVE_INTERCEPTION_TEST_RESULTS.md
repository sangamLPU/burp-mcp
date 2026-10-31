# Live interception test results

- **Date:** 2026-10-31
- **Burp:** Suite Professional 2024.1.1.1-26891
- **MCP extension:** v1.3.1, build `20261031.1-burp2024.1.1.1`
- **Target and proxy:** loopback test server `127.0.0.1:8000`, Burp Proxy `127.0.0.1:8080`
- **MCP tool inventory:** 70 tools

All traffic in these checks stayed on loopback. Burp bearer authentication remained required, the host was allowlisted and in scope, and human disclosure/edit approval remained enabled. Native Proxy Intercept was kept off; interception used the extension-managed queue. Each edited revision was locally approved at its exact revision and released once.

## Functional checks

| Check | Original local message | Approved edit | Verification | Result |
|---|---|---|---|---|
| POST JSON | POST /test-post; synthetic JSON test request. | Changed only the dedicated test field and preserved the other field. | Loopback server observation and client echo confirmed the intended change; HTTP 200 and matching body lengths. | **PASS** |
| Request cookie | GET /test-cookie with a dedicated synthetic test cookie; values omitted. | Changed only the test cookie value; no other cookies were present. | Server observation confirmed the test cookie edit; client received HTTP 200. The response was approved and forwarded unchanged. | **PASS** |
| Set-Cookie response | GET /test-set-cookie; server returned a dedicated synthetic cookie with Path and SameSite attributes. | Changed only the synthetic cookie value; preserved its attributes. | Client response headers confirmed the test cookie edit and preserved attributes; HTTP 200. | **PASS** |
| HTML response body | GET /test-html; the original page contained a test heading and a separate paragraph. | Replaced only the heading; preserved the paragraph and surrounding HTML. | Loopback client confirmed the modified heading and preserved paragraph; HTTP 200 and matching Content-Length. | **PASS** |
| Burp browser rendering | GET /test-html in Burp's bundled Chromium. | Forwarded the locally approved response revision with the heading edit. | User visually confirmed ?Modified by Burp MCP? displayed and the original paragraph remained visible. | **PASS** |

For each edit, the exact proposed revision was approved locally before it was forwarded. The unedited requests needed to reach the response tests were also approved before release. The client/server observations establish delivery; a proposal or an approval by itself is not delivery evidence.

One earlier malformed POST client construction produced invalid JSON. That message was left untouched and expired at the configured 120-second deadline; it did not reach the server. The successful POST used a fresh request ID. There were exactly four server requests in the successful run, one for each endpoint, with no duplicate delivery observed.

## Shutdown and diagnostics

After the tests, both pending queues were empty. Live interception was disabled locally and the status reported `heartbeatHealth=STOPPED`, `sessionEndReason=DISABLED`, zero pending requests, and zero pending responses. The MCP server remained connected and reported `lastError=null`; all 70 Burp tools remained registered. The recent, payload-free diagnostic events showed the disable confirmation and clean queue reads. The diagnostic ring is bounded to its latest 100 events, so it is not a complete historical ledger of every test event. The server-side endpoint counts above independently show one delivered request per successful check.

This report contains no raw HTTP captures, bearer tokens, real credentials, cookie values, or message IDs. The final local test-server observation log remains under the ignored build directory and contains only timestamp, method, path, byte counts, and test-match booleans; the helper does not persist request bodies or Cookie headers. The working MCP extension source and JAR were not changed or rebuilt.

## Scope and limitations

- Verified: live Burp callbacks for one local POST body edit, one local request-cookie edit, one local `Set-Cookie` edit, and one local HTML-body edit; exact-revision local approval; one-time forwarding; observed server/client delivery; and framing for the tested textual bodies.
- Not covered: public targets, HTTPS/TLS, HTTP/2, compressed or binary bodies, streaming, WebSockets, HTTP/3, concurrent load, or interactions with other Burp extensions.
- Body editing is limited to bounded uncompressed textual content. Host/routing and framing headers are protected. Forwarding releases a message to Burp; only the observed client/server result proves network delivery.
- Burp HTTP history can expose original and modified messages separately, and its default message view is configurable. This run did not inspect the current history display preference. The MCP history response tools read `originalResponse()` in the current source, so their response output is not proof of the final downstream bytes. The client captures above are the delivery evidence. See [Burp HTTP history](https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history) and [Proxy settings](https://portswigger.net/burp/documentation/desktop/settings/tools/proxy).

## Burp Browser “Error Loading Extension” diagnosis

The MCP extension was not implicated: its server stayed healthy, and all four live-edit checks passed. Burp 2024.1.1.1 ships Windows Chromium 121.0.6167.161 ([PortSwigger release notes](https://portswigger.net/burp/releases/professional-community-2024-1-1-1)). The Burp-launched browser points `--load-extension` at Burp's separate `burp-chromium-extension` directory. In that browser's profile, the entry for that exact extension path is disabled (`state=0`, `disable_reasons=1`). Chromium defines bit 0 as `DISABLE_USER_ACTION` ([Chromium source](https://chromium.googlesource.com/chromium/src/%2B/426ccf4bf59d1b1c6bc716f0c08c1af955f77aa3/extensions/browser/disable_reason.h)). This is a concrete profile-level reason the pre-wired Burp extension is unavailable; the original action that disabled it is not recoverable from the current profile state.

The extracted Burp extension manifest is Manifest V2. Chromium 121 predates the Manifest V2 disablement cutoff, so that policy transition does not explain this specific profile state ([Chrome's support timeline](https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline)). Separately, the extracted manifest lists root `settings.json` as a web-accessible resource and its content script requests that resource, but the file is absent. That is an installed-asset anomaly; no runtime error was captured that proves it caused the displayed page, so no guessed replacement file was added.

**Burp browser recovery:** The user re-enabled the bundled Burp Suite extension in Burp Chromium. The final rendering check used the existing working MCP extension and JAR; neither was rebuilt or modified.

**Verified browser-rendering test (PASS):** On 2026-10-31, the user opened the loopback test page in Burp's browser. The matching response was disclosed with local approval, the heading-only proposal was approved at its exact revision, and that response revision was forwarded once. The user visually confirmed that ?Modified by Burp MCP? appeared and the original paragraph remained visible. This is user-provided visual confirmation; the earlier curl checks remain separate HTTP-delivery evidence.
