import unittest

from cancel_test_preflight import (
    EXPECTED_BUILD_ID,
    TARGET_URL,
    validate_mcp_snapshot,
)


def valid_snapshot():
    return {
        "connection": {
            "burpConnected": True,
            "serverState": "running",
            "burpVersion": "Burp Suite Professional 2024.1.1.1-26891",
        },
        "server": {
            "serverState": "running",
            "lastError": None,
            "buildId": EXPECTED_BUILD_ID,
            "bearerAuthenticationRequired": True,
            "readOnlyMode": False,
        },
        "scope": {
            "checks": [{
                "url": TARGET_URL,
                "inBurpScope": True,
                "hostAllowlisted": True,
                "eligible": True,
            }],
        },
        "interception": {
            "enabled": True,
            "heartbeatHealth": "HEALTHY",
            "sessionLifetimeSeconds": 300,
            "sessionRemainingMillis": 299_000,
            "leaseRemainingMillis": 14_000,
            "sessionEndReason": "NONE",
            "pendingRequests": 0,
            "pendingResponses": 0,
        },
        "requests": [],
        "responses": [],
    }


class CancellationPreflightTests(unittest.TestCase):
    def test_all_prerequisites_pass(self):
        self.assertEqual([], validate_mcp_snapshot(valid_snapshot()))

    def test_expired_or_absent_session_fails(self):
        snapshot = valid_snapshot()
        snapshot["interception"].update({
            "enabled": False,
            "heartbeatHealth": "EXPIRED",
            "sessionRemainingMillis": 0,
            "sessionEndReason": "SESSION_EXPIRED",
        })
        failures = validate_mcp_snapshot(snapshot)
        self.assertIn("Live interception is not active", failures)
        self.assertIn("Live interception heartbeat is not healthy", failures)
        self.assertIn("Less than four minutes remain in the approved session", failures)

    def test_insufficient_remaining_time_fails(self):
        snapshot = valid_snapshot()
        snapshot["interception"]["sessionRemainingMillis"] = 239_999
        self.assertIn(
            "Less than four minutes remain in the approved session",
            validate_mcp_snapshot(snapshot),
        )

    def test_scope_and_allowlist_are_independent_requirements(self):
        snapshot = valid_snapshot()
        snapshot["scope"]["checks"][0]["hostAllowlisted"] = False
        snapshot["scope"]["checks"][0]["eligible"] = False
        failures = validate_mcp_snapshot(snapshot)
        self.assertIn("/test-cancel host is not in the MCP allowlist", failures)
        self.assertIn("/test-cancel is not eligible", failures)

    def test_nonempty_or_unavailable_queues_fail(self):
        snapshot = valid_snapshot()
        snapshot["interception"]["pendingRequests"] = 1
        snapshot["requests"] = [{"id": "held"}]
        snapshot["responses"] = None
        failures = validate_mcp_snapshot(snapshot)
        self.assertIn("Interception request queue is not empty", failures)
        self.assertIn("Pending request listing is missing or non-empty", failures)
        self.assertIn("Pending response listing is missing or non-empty", failures)

    def test_wrong_build_or_burp_version_fails(self):
        snapshot = valid_snapshot()
        snapshot["server"]["buildId"] = "stale-build"
        snapshot["connection"]["burpVersion"] = "Burp Suite Professional 2023.1"
        failures = validate_mcp_snapshot(snapshot)
        self.assertIn(f"Loaded extension build does not match expected build {EXPECTED_BUILD_ID}", failures)
        self.assertIn("Burp version does not match Professional 2024.1.1.1", failures)

    def test_missing_snapshot_fails_closed(self):
        failures = validate_mcp_snapshot({})
        self.assertTrue(failures)
        self.assertIn("Live interception is not active", failures)

    def test_unattended_preflight_requires_current_matching_burp_and_server_identity(self):
        snapshot = valid_snapshot()
        run_id = "11111111-2222-3333-4444-555555555555"
        server_identity = "A" * 43
        snapshot["interception"]["unattendedMode"] = {
            "active": True,
            "testRunId": run_id,
            "serverIdentity": server_identity,
        }
        self.assertEqual([], validate_mcp_snapshot(
            snapshot, unattended_run_id=run_id, unattended_server_identity=server_identity
        ))
        self.assertIn("Supplied test identity does not match the active Burp-local authorization", validate_mcp_snapshot(
            snapshot, unattended_run_id=run_id, unattended_server_identity="B" * 43
        ))
        snapshot["interception"]["unattendedMode"]["active"] = False
        self.assertIn("Unattended local test mode is not active for the supplied test identity", validate_mcp_snapshot(
            snapshot, unattended_run_id=run_id, unattended_server_identity=server_identity
        ))


if __name__ == "__main__":
    unittest.main()
