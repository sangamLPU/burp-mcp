"""Offline regressions for rule readiness and approval-wait coordination."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from live_rule_engine_coordinator import (
    CORE_ACTIVE_RULES,
    PAUSE_REQUEST_RULE,
    PAUSE_RESPONSE_RULE,
    REQUEST_RULE,
    RESPONSE_RULE,
    RULE_NAMES,
    EXPECTED_BUILD_ID,
    CoordinatorError,
    LiveRuleEngineCoordinator,
    WaitingForApproval,
    build_rule_specs,
    require_pretraffic_readiness,
    response_wait_state,
    rule_readiness_failures,
)


RUN_ID = "11111111-2222-3333-4444-555555555555"


def rule_entries(active_names=CORE_ACTIVE_RULES):
    return [
        {"id": f"id-{spec['name']}", "spec": copy.deepcopy(spec),
         "state": "ACTIVE" if spec["name"] in active_names else "DISABLED"}
        for spec in build_rule_specs(RUN_ID)
    ]


def ready_status():
    return {
        "enabled": True,
        "heartbeatHealth": "HEALTHY",
        "sessionRemainingMillis": 55_000,
        "pendingRequests": 0,
        "pendingResponses": 0,
        "unattendedMode": {"active": True, "testRunId": RUN_ID,
                           "serverIdentity": "A" * 43, "remainingMillis": 120_000},
    }


class LiveRuleCoordinatorRegressionTests(unittest.TestCase):
    def test_loaded_kotlin_catalog_omits_default_action_and_priority(self):
        rules = rule_entries()
        for entry in rules:
            if entry["spec"]["action"] == "MODIFY_AND_FORWARD":
                del entry["spec"]["action"]
                del entry["spec"]["priority"]
        self.assertEqual([], rule_readiness_failures(rules, RUN_ID))
        rules[0]["spec"]["priority"] = 99
        self.assertTrue(rule_readiness_failures(rules, RUN_ID))

    def test_loaded_rule_statistics_are_a_single_record_array(self):
        class Client:
            def tool(self, name, **kwargs):
                return [{"ruleId": "one", "matchedResponses": 8}]
        coordinator = LiveRuleEngineCoordinator(Client())
        self.assertEqual(8, coordinator.tool("burp_get_interception_rule_stats", ruleId="one")["matchedResponses"])
        self.assertIsInstance(coordinator.tool("burp_get_interception_rule_stats"), list)

    def test_fixture_handoff_uses_json_and_files_instead_of_inherited_pipes(self):
        coordinator = LiveRuleEngineCoordinator(object())
        coordinator.run_id = RUN_ID
        coordinator.server_identity = "A" * 43
        def launch(args, **kwargs):
            self.assertIn("-Command", args)
            self.assertIn("ConvertTo-Json -Compress", args[-1])
            self.assertNotIn("capture_output", kwargs)
            self.assertNotIn("BURP_MCP_TOKEN", kwargs["env"])
            kwargs["stdout"].write(json.dumps({"State": "READY", "ProcessId": 123,
                                               "RuleEngineTestMode": True}).encode())
            return subprocess.CompletedProcess(args, 0)
        with tempfile.TemporaryDirectory() as directory:
            coordinator.evidence_path = Path(directory) / "evidence.jsonl"
            with patch("live_rule_engine_coordinator.subprocess.run", side_effect=launch):
                with patch("live_rule_engine_coordinator.preflight.check_test_server_health") as health:
                    coordinator._start_fixture()
            health.assert_called_once_with(RUN_ID, "A" * 43)
        self.assertEqual(123, coordinator.fixture_pid)
        self.assertTrue(coordinator.fixture_mode)

    def test_rule_specs_pair_request_and_response_at_same_priority(self):
        specs = {spec["name"]: spec for spec in build_rule_specs(RUN_ID)}
        self.assertEqual(set(specs), set(RULE_NAMES))
        self.assertEqual(specs[REQUEST_RULE]["priority"], specs[RESPONSE_RULE]["priority"])
        self.assertEqual(specs[REQUEST_RULE]["direction"], "REQUEST")
        self.assertEqual(specs[RESPONSE_RULE]["direction"], "RESPONSE")
        self.assertEqual(specs[RESPONSE_RULE]["conditions"]["responseStatus"], 200)
        self.assertEqual(specs[RESPONSE_RULE]["conditions"]["jsonPath"], "$.enabled")
        self.assertEqual(specs[RESPONSE_RULE]["conditions"]["jsonValueJson"], "false")
        self.assertEqual(specs[REQUEST_RULE]["conditions"]["jsonValueJson"], "false")

    def test_exact_failed_setup_is_rejected_before_first_request(self):
        rules = rule_entries(active_names=frozenset((REQUEST_RULE,)))
        engine = {"configuredRules": len(RULE_NAMES), "enabledRules": 1, "emergencyStopped": False}
        with self.assertRaises(CoordinatorError) as raised:
            require_pretraffic_readiness(ready_status(), engine, rules, RUN_ID)
        self.assertEqual(raised.exception.code, "READINESS_FAILED")
        self.assertIn("LIVE-RULE-RESPONSE-JSON state is DISABLED", str(raised.exception))
        self.assertIn("no request was sent", str(raised.exception))

    def test_disabled_response_during_exchange_is_reported_as_waiting_for_approval(self):
        response = next(item for item in rule_entries() if item["spec"]["name"] == RESPONSE_RULE)
        response["state"] = "DISABLED"
        state, reason = response_wait_state([{"id": "synthetic-response"}], response, 0, 0)
        self.assertEqual(state, "WAITING_FOR_APPROVAL")
        self.assertIn("not active", reason)

    def test_active_but_unmatched_response_reports_waiting_without_approval(self):
        response = next(item for item in rule_entries() if item["spec"]["name"] == RESPONSE_RULE)
        state, reason = response_wait_state([{"id": "synthetic-response"}], response, 0, 0,
                                            processing_grace_elapsed=True)
        self.assertEqual(state, "WAITING_FOR_APPROVAL")
        self.assertIn("no response rule matched", reason)

    def test_matched_response_is_given_a_short_processing_grace(self):
        response = next(item for item in rule_entries() if item["spec"]["name"] == RESPONSE_RULE)
        state, reason = response_wait_state([{"id": "synthetic-response"}], response, 0, 1)
        self.assertEqual((state, reason), ("PROCESSING", None))

    def test_failed_or_skipped_response_is_reported_without_waiting_for_client_timeout(self):
        response = next(item for item in rule_entries() if item["spec"]["name"] == RESPONSE_RULE)
        state, reason = response_wait_state(
            [{"id": "synthetic-response"}], response, 0, 1,
            failures_before=0, failures_after=1, last_error_code="RESPONSE_NOT_ASSOCIATED",
        )
        self.assertEqual(state, "WAITING_FOR_APPROVAL")
        self.assertIn("RESPONSE_NOT_ASSOCIATED", reason)
        state, reason = response_wait_state(
            [{"id": "synthetic-response"}], response, 0, 0,
            skipped_before=0, skipped_after=1,
        )
        self.assertEqual(state, "WAITING_FOR_APPROVAL")
        self.assertIn("manual approval", reason)

    def test_native_intercept_confirmation_happens_before_session_start(self):
        class Client:
            def __init__(self):
                self.events = []
                self.status_reads = 0

            def tool(self, name, **args):
                self.events.append((name, args))
                if name == "burp_get_intercept_status":
                    self.status_reads += 1
                    if self.status_reads == 1:
                        return {"unattendedMode": {"remainingMillis": 120_000}}
                    return ready_status()
                if name == "burp_list_interception_rules":
                    return rule_entries()
                if name == "burp_get_rule_engine_status":
                    return {"configuredRules": len(RULE_NAMES), "enabledRules": len(CORE_ACTIVE_RULES),
                            "emergencyStopped": False}
                return {}

        client = Client()
        coordinator = LiveRuleEngineCoordinator(client)
        coordinator.run_id = RUN_ID
        coordinator.server_identity = "A" * 43
        coordinator.rule_ids = {name: f"id-{name}" for name in RULE_NAMES}
        coordinator.rules = rule_entries(frozenset())

        coordinator._start_session_and_enable_rules()

        event_names = [name for name, _ in client.events]
        self.assertLess(event_names.index("burp_set_proxy_intercept_state"),
                        event_names.index("burp_set_live_interception_state"))
        session_start = event_names.index("burp_set_live_interception_state")
        first_enable = event_names.index("burp_enable_interception_rule")
        self.assertLess(session_start, first_enable)
        self.assertEqual(len([name for name in event_names if name == "burp_enable_interception_rule"]),
                         len(CORE_ACTIVE_RULES))
        self.assertEqual(rule_readiness_failures(coordinator.rules, RUN_ID, CORE_ACTIVE_RULES), [])

    def test_offline_coordinator_runs_request_response_pause_resume_and_cleanup_sequence(self):
        expected_stats = {
            REQUEST_RULE: {"matchedRequests": 8, "modified": 8, "forwarded": 8},
            RESPONSE_RULE: {"matchedResponses": 8, "modified": 8, "forwarded": 8},
            "LIVE-RULE-REQUEST-HEADER": {"matchedRequests": 2, "modified": 2, "forwarded": 2},
            PAUSE_REQUEST_RULE: {"matchedRequests": 1, "modified": 0, "forwarded": 1},
            PAUSE_RESPONSE_RULE: {"matchedResponses": 1, "modified": 0, "forwarded": 1},
        }

        class Client:
            def __init__(self):
                self.rule_states = {}
                self.status_reads = 0

            def tool(self, name, **args):
                if name == "burp_get_intercept_status":
                    self.status_reads += 1
                    if self.status_reads == 1:
                        return {"enabled": True, "pendingRequests": 0, "pendingResponses": 0}
                    return {"enabled": False, "heartbeatHealth": "EXPIRED", "sessionEndReason": "SESSION_EXPIRED",
                            "pendingRequests": 0, "pendingResponses": 0}
                if name == "burp_get_interception_rule":
                    return {"state": self.rule_states[args["ruleId"]]}
                if name == "burp_list_interception_rules":
                    return [
                        {"id": f"id-{spec['name']}", "spec": copy.deepcopy(spec),
                         "state": self.rule_states[f"id-{spec['name']}"]}
                        for spec in build_rule_specs(RUN_ID)
                    ]
                if name == "burp_get_interception_rule_stats":
                    rule_name = args["ruleId"].removeprefix("id-")
                    return {**expected_stats[rule_name], "failed": 0, "dropped": 0, "skipped": 0}
                if name == "burp_disable_interception_rule":
                    self.rule_states[args["ruleId"]] = "PAUSED"
                    return {}
                if name == "burp_enable_interception_rule":
                    self.rule_states[args["ruleId"]] = "ACTIVE"
                    return {}
                if name == "burp_delete_interception_rule":
                    del self.rule_states[args["ruleId"]]
                    return {}
                if name == "burp_get_rule_engine_status":
                    return {"configuredRules": len(self.rule_states)}
                return {}

        class Coordinator(LiveRuleEngineCoordinator):
            @staticmethod
            def _snapshot(client):
                return {"server": {"buildId": EXPECTED_BUILD_ID}}

            def _validate_initial(self, snapshot):
                return RUN_ID, "A" * 43

            def _stop_empty_session_before_setup(self):
                pass

            def _start_fixture(self):
                self.fixture_pid = 1

            def _create_rules_before_session(self):
                self.rule_ids = {name: f"id-{name}" for name in RULE_NAMES}
                self.client.rule_states = {rule_id: "DISABLED" for rule_id in self.rule_ids.values()}
                self.rules = rule_entries(frozenset())

            def _start_session_and_enable_rules(self):
                for name in CORE_ACTIVE_RULES:
                    self.client.rule_states[self.rule_ids[name]] = "ACTIVE"
                self.rules = rule_entries()
                self.response_rule = next(row for row in self.rules if row["spec"]["name"] == RESPONSE_RULE)

            def _exchange(self, case_id, *, expected_enabled=True, rule_header=False, pause_header=False,
                          response_rule_name=RESPONSE_RULE):
                self.exchanges.append((case_id, expected_enabled, rule_header, pause_header, response_rule_name))
                return {"case": case_id, "status": 200, "clientEnabled": expected_enabled,
                        "originEnabled": expected_enabled, "originDeliveryCount": 1}

            def _origin_records(self):
                return [{"ruleTestId": case_id} for case_id, *_ in self.exchanges]

            def _stop_fixture(self):
                self.fixture_pid = None
                self.fixture_stopped = True

            def __init__(self, client):
                super().__init__(client)
                self.exchanges = []
                self.fixture_stopped = False

        coordinator = Coordinator(Client())
        with patch("live_rule_engine_coordinator.preflight.check_proxy_listener"):
            result = coordinator.run()

        self.assertEqual(result["state"], "PASS")
        self.assertFalse(result["liveProxy"] is False)
        self.assertEqual(result["exchangeCount"], 9)
        self.assertEqual(len(result["exchanges"]), 9)
        self.assertEqual(result["clientResponsesVerified"], 9)
        self.assertEqual(result["originDeliveriesVerified"], 9)
        self.assertTrue(result["multipleRulesVerified"])
        self.assertTrue(result["pauseResumeVerified"])
        self.assertTrue(result["cleanup"]["rulesDeleted"])
        self.assertTrue(coordinator.fixture_stopped)
        self.assertEqual(len({case_id for case_id, *_ in coordinator.exchanges}), 9)
        self.assertEqual(sum(rule_header for _, _, rule_header, _, _ in coordinator.exchanges), 2)
        self.assertEqual(sum(pause_header for _, _, _, pause_header, _ in coordinator.exchanges), 1)
        self.assertTrue(all(expected is False for _, expected, _, pause_header, _ in coordinator.exchanges
                            if pause_header))

    def test_preapproved_native_intercept_does_not_reprompt_inside_authorization_window(self):
        coordinator = LiveRuleEngineCoordinator(object(), native_intercept_prepared=True)
        coordinator.run_id = RUN_ID
        coordinator.rule_ids = {name: f"id-{name}" for name in RULE_NAMES}
        results = {
            "burp_get_intercept_status": ready_status(),
            "burp_list_interception_rules": rule_entries(),
            "burp_get_rule_engine_status": {"configuredRules": 5, "enabledRules": 3, "emergencyStopped": False},
        }
        with patch.object(coordinator, "tool", side_effect=lambda name, **kwargs: results.get(name, {})) as tool:
            coordinator._start_session_and_enable_rules()
        names = [call.args[0] for call in tool.call_args_list]
        self.assertNotIn("burp_set_proxy_intercept_state", names)
        self.assertLess(names.index("burp_set_live_interception_state"), names.index("burp_enable_interception_rule"))

    def test_pause_fallback_rules_are_disabled_before_traffic(self):
        failures = rule_readiness_failures(rule_entries(), RUN_ID, CORE_ACTIVE_RULES)
        self.assertEqual(failures, [])
        paused_states = frozenset((PAUSE_REQUEST_RULE, PAUSE_RESPONSE_RULE))
        failures = rule_readiness_failures(rule_entries(paused_states), RUN_ID, paused_states)
        self.assertEqual(failures, [])

    def test_approval_gated_response_stops_coordinator_without_retry_or_later_exchange(self):
        class Clock:
            now = 0.0

            def __call__(self):
                return self.now

            def sleep(self, seconds):
                self.now += seconds

        class Client:
            def __init__(self):
                self.calls = []

        class Coordinator(LiveRuleEngineCoordinator):
            def __init__(self, client, clock):
                super().__init__(client, clock=clock, sleeper=clock.sleep, http_timeout=2)
                self.client_started = threading.Event()
                self.release_client = threading.Event()
                self.fixture_stopped = False

            @staticmethod
            def _snapshot(client):
                return {"server": {"buildId": EXPECTED_BUILD_ID}}

            def _validate_initial(self, snapshot):
                return RUN_ID, "A" * 43

            def _stop_empty_session_before_setup(self):
                pass

            def _start_fixture(self):
                self.fixture_pid = 1

            def _create_rules_before_session(self):
                self.rule_ids = {name: f"id-{name}" for name in RULE_NAMES}
                self.rules = rule_entries(frozenset())

            def _start_session_and_enable_rules(self):
                self.rules = rule_entries()
                self.response_rule = next(row for row in self.rules if row["spec"]["name"] == RESPONSE_RULE)

            def _http_post(self, *args, **kwargs):
                self.client.client_attempts = getattr(self.client, "client_attempts", 0) + 1
                self.client_started.set()
                self.release_client.wait(2)
                raise TimeoutError("synthetic offline client remains waiting")

            def _stop_fixture(self):
                self.fixture_stopped = True
                self.release_client.set()

            def tool(self, name, **args):
                self.client.calls.append((name, args))
                if name == "burp_get_interception_rule_stats":
                    return {"matchedResponses": 0}
                if name == "burp_get_intercept_status":
                    return {"enabled": True, "heartbeatHealth": "HEALTHY", "sessionRemainingMillis": 50_000}
                if name == "burp_list_pending_responses":
                    return [{"id": "held-response"}]
                if name == "burp_list_interception_rules":
                    return []
                return {}

        client = Client()
        clock = Clock()
        coordinator = Coordinator(client, clock)
        with patch("live_rule_engine_coordinator.preflight.check_proxy_listener"):
            with self.assertRaises(WaitingForApproval) as raised:
                coordinator.run()

        self.assertEqual(raised.exception.code, "WAITING_FOR_APPROVAL")
        self.assertEqual(client.client_attempts, 1)
        self.assertTrue(coordinator.fixture_stopped)
        self.assertTrue(coordinator.waiting_for_approval)
        self.assertEqual(coordinator.client_attempts_started, 1)
        self.assertTrue(coordinator.owned_rules_deleted)
        self.assertFalse(any(name in {"burp_forward_intercepted_response", "burp_drop_intercepted_response"}
                             for name, _ in client.calls))
        self.assertEqual(sum(name == "burp_disable_interception_rule" for name, _ in client.calls), len(RULE_NAMES))
        self.assertEqual(sum(name == "burp_delete_interception_rule" for name, _ in client.calls), len(RULE_NAMES))


if __name__ == "__main__":
    unittest.main()
