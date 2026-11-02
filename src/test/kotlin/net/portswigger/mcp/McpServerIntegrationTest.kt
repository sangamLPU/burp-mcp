package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.ktor.client.HttpClient
import io.ktor.client.plugins.sse.SSE
import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.config.LocalTestTargets
import net.portswigger.mcp.intercept.LiveInterception
import net.portswigger.mcp.intercept.LocalTestManagementOperation
import net.portswigger.mcp.intercept.LocalTestPolicyDecision
import net.portswigger.mcp.security.ActivityLog
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Tag
import java.net.ServerSocket

@Tag("loopback")
class McpServerIntegrationTest {
    private val client = TestStreamableHttpMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val live by lazy { LiveInterception(api, config) }
    private val serverManager by lazy { KtorServerManager(api, live) }
    private val testPort = findAvailablePort()
    private val persistedObject = mockk<PersistedObject>()
    @Volatile private var serverStarted = false
    @Volatile private var serverFailure: Throwable? = null

    private fun assertReportedBuildIdentity(result: CallToolResult?, toolName: String) {
        assertNotNull(result, "$toolName should return a result")
        val text = (result!!.content.singleOrNull() as? TextContent)?.text
        assertNotNull(text, "$toolName should return one JSON text content item")
        val identity = Json.parseToJsonElement(text!!).jsonObject
        assertEquals(BuildInfo.version, identity["extensionVersion"]?.jsonPrimitive?.content)
        assertEquals(BuildInfo.buildId, identity["buildId"]?.jsonPrimitive?.content)
    }

    init {
        every { persistedObject.getBoolean(any()) } returns true
        every { persistedObject.getString(any()) } returns "127.0.0.1"
        every { persistedObject.getInteger(any()) } returns null
        every { persistedObject.getInteger("port") } returns testPort
        every { persistedObject.setBoolean(any(), any()) } returns Unit
        every { persistedObject.setString(any(), any()) } returns Unit
        every { persistedObject.setInteger(any(), any()) } returns Unit
    }

    private val mockLogging = mockk<Logging>().apply {
        every { logToError(any<String>()) } returns Unit
        every { logToOutput(any<String>()) } returns Unit
    }

    private val config = McpConfig(persistedObject, mockLogging)

    @BeforeEach
    fun setup() {
        every { api.burpSuite().version().edition() } returns BurpSuiteEdition.PROFESSIONAL
        serverManager.start(config) { state ->
            if (state is ServerState.Running) {
                serverStarted = true
            }
            if (state is ServerState.Failed) serverFailure = state.exception
        }
        
        runBlocking {
            var attempts = 0
            while (!serverStarted && serverFailure == null && attempts < 100) {
                delay(100)
                attempts++
            }
            
            if (!serverStarted) {
                throw IllegalStateException("Server failed to start after timeout", serverFailure)
            }
            client.connectToServer("http://127.0.0.1:${testPort}/mcp", config.bearerToken)
        }
    }

    private fun findAvailablePort(): Int {
        return ServerSocket(0).use { it.localPort }
    }

    @AfterEach
    fun tearDown() {
        runBlocking {
            if (client.isConnected()) {
                client.close()
            }
        }
        serverManager.shutdown()
        live.close()
    }

    @Test
    fun `server should accept connections and list tools`() = runBlocking {
        try {
            assertTrue(client.isConnected(), "Client should be connected to server")
            
            val tools = client.listTools()
            assertFalse(tools.isEmpty(), "Server should have registered tools")
            assertEquals(86, tools.size, "The Professional MCP catalog must retain the existing tools and expose the bounded interception-rule API")
            assertEquals(tools.size, tools.map { it.name }.toSet().size, "MCP tool names must be unique")
            val expectedToolNames = setOf(
                "base64_decode", "base64_encode",
                "burp_analyze_authentication", "burp_analyze_cookies", "burp_analyze_cors",
                "burp_analyze_request", "burp_analyze_response", "burp_analyze_security_headers",
                "burp_approve_intercepted_request_edit", "burp_approve_intercepted_response_edit",
                "burp_cancel_interceptions", "burp_check_connection", "burp_compare_responses",
                "burp_configure_local_test_scope", "burp_drop_intercepted_request", "burp_drop_intercepted_response",
                "burp_find_sensitive_data", "burp_forward_intercepted_request", "burp_forward_intercepted_response",
                "burp_generate_security_report", "burp_get_capabilities", "burp_get_intercept_diagnostics",
                "burp_get_intercept_status", "burp_get_intercepted_request", "burp_get_intercepted_response",
                "burp_get_project_info", "burp_get_proxy_history", "burp_get_repeater_tabs", "burp_get_request",
                "burp_get_response", "burp_get_response_headers", "burp_get_scan_status", "burp_get_scanner_issues",
                "burp_get_scope", "burp_get_site_map", "burp_get_status", "burp_list_pending_requests",
                "burp_create_interception_rule", "burp_list_interception_rules", "burp_get_interception_rule",
                "burp_update_interception_rule", "burp_enable_interception_rule", "burp_disable_interception_rule",
                "burp_delete_interception_rule", "burp_clear_interception_rules", "burp_preview_interception_rule",
                "burp_get_interception_rule_stats", "burp_get_interception_rule_events", "burp_get_rule_engine_status",
                "burp_clear_interception_rule_stats", "burp_pause_all_interception_rules", "burp_emergency_stop_rules",
                "burp_list_pending_responses", "burp_modify_request", "burp_propose_intercepted_request_edit",
                "burp_propose_intercepted_response_edit", "burp_request_intercept_disclosure",
                "burp_search_http_history", "burp_send_http_request", "burp_send_to_repeater",
                "burp_set_live_interception_state", "burp_set_proxy_intercept_state", "burp_start_scan",
                "burp_stop_scan", "create_repeater_tab", "create_repeater_tab_http2",
                "generate_collaborator_payload", "generate_random_string", "get_active_editor_contents",
                "get_collaborator_interactions", "get_organizer_items", "get_organizer_items_regex",
                "get_proxy_http_history", "get_proxy_http_history_regex", "get_scanner_issues",
                "output_project_options", "output_user_options", "send_http1_request", "send_http2_request",
                "set_active_editor_contents", "set_project_options", "set_proxy_intercept_state",
                "set_task_execution_engine_state", "set_user_options", "url_decode", "url_encode"
            )
            assertEquals(expectedToolNames, tools.map { it.name }.toSet(), "The Professional tool contract must not lose or rename an existing tool")
            assertTrue(tools.any { it.name == "burp_configure_local_test_scope" })
            assertTrue(tools.any { it.name == "burp_get_intercepted_request" })
            assertTrue(tools.any { it.name == "burp_forward_intercepted_response" })
            assertTrue(tools.any { it.name == "burp_get_intercept_diagnostics" })
            tools.forEach { tool ->
                assertEquals("object", tool.inputSchema.type, "${tool.name} must expose an object input schema")
                assertFalse(tool.description.isNullOrBlank(), "${tool.name} must document its behavior")
                val properties = tool.inputSchema.properties
                val required = tool.inputSchema.required.orEmpty()
                assertTrue(required.all { properties?.containsKey(it) == true }, "${tool.name} required fields must exist in properties")
                properties?.forEach { (propertyName, schema) ->
                    assertTrue(schema is JsonObject, "${tool.name}.$propertyName must have a JSON object schema")
                    assertTrue((schema as JsonObject).containsKey("type"), "${tool.name}.$propertyName must declare a schema type")
                }
            }
            
            val toolNames = tools.map { it.name }
            assertTrue(toolNames.contains("output_project_options"), "Server should have output_project_options tool")
            assertTrue(toolNames.contains("output_user_options"), "Server should have output_user_options tool")
            assertTrue(toolNames.contains("burp_get_status"), "Server should expose the Burp API tools")
            assertTrue(toolNames.contains("burp_get_capabilities"), "Server should expose the Burp capability tool")
            val status = client.callTool("burp_get_status", emptyMap())
            assertReportedBuildIdentity(status, "burp_get_status")

            val capabilities = client.callTool("burp_get_capabilities", emptyMap())
            assertReportedBuildIdentity(capabilities, "burp_get_capabilities")
            
            val pingResult = client.ping()
            assertNotNull(pingResult, "Ping should return a result")
        } catch (e: Exception) {
            fail("Connection failed: ${e.message}")
        }
    }

    @Test
    fun `MCP endpoint rejects requests without bearer authentication`() = runBlocking {
        val httpClient = HttpClient { install(SSE) }
        try {
            val response = httpClient.get("http://127.0.0.1:$testPort/mcp")
            assertEquals(HttpStatusCode.Unauthorized, response.status)
        } finally {
            httpClient.close()
        }
    }

    @Test
    fun `nested interception rule schema and authenticated create workflow work`() = runBlocking {
        every { persistedObject.getBoolean("readOnlyMode") } returns false
        every { persistedObject.getString("_autoApproveTargets") } returns LocalTestTargets.ALLOWLIST_ENTRY
        config.readOnlyMode = false
        config.autoApproveTargets = LocalTestTargets.ALLOWLIST_ENTRY
        every { api.scope().isInScope(any()) } returns true
        val createTool = client.listTools().single { it.name == "burp_create_interception_rule" }
        val specSchema = createTool.inputSchema.properties?.get("spec") as JsonObject
        assertTrue(specSchema["properties"]!!.jsonObject.containsKey("conditions"))
        assertTrue(specSchema["properties"]!!.jsonObject.containsKey("maximumModifications"))
        val transformationSchema = specSchema["properties"]!!.jsonObject["transformations"]!!.jsonObject
        assertEquals("array", transformationSchema["type"]!!.jsonPrimitive.content)
        val itemSchema = transformationSchema["items"]!!.jsonObject
        assertTrue(itemSchema["properties"]!!.jsonObject.containsKey("type"))

        live.activateUnattendedLocalTestMode(60)
        val runId = live.unattendedSnapshot().testRunId!!
        assertEquals(listOf(LocalTestTargets.ALLOWLIST_ENTRY), config.getAutoApproveTargetsList())
        assertEquals(LocalTestPolicyDecision.AUTO_APPROVE,
            live.unattendedManagementDecision(LocalTestManagementOperation.CONFIGURE_RULE).decision)
        val created = client.callTool("burp_create_interception_rule", mapOf(
            "spec" to mapOf(
                "name" to "Enable synthetic JSON field",
                "targetUrl" to LocalTestTargets.urls.first(),
                "authorizationReference" to runId,
                "direction" to "REQUEST",
                "conditions" to mapOf("jsonPath" to "$.enabled", "jsonValueJson" to "false"),
                "transformations" to listOf(mapOf("type" to "SET_JSON_FIELD", "path" to "$.enabled", "valueJson" to "true")),
                "action" to "MODIFY_AND_FORWARD",
                "priority" to 100,
                "maximumMatches" to 5,
                "maximumModifications" to 4,
                "durationSeconds" to 60
            )
        ))!!
        assertFalse(created.isError == true, created.content.toString())
        assertTrue(created.content.toString().contains("DISABLED"))
        assertTrue(created.content.toString().contains("maximumModifications"))

        val listed = client.callTool("burp_list_interception_rules", mapOf("includeDiagnostics" to false))!!
        assertFalse(listed.isError == true)
        assertTrue(listed.content.toString().contains("Enable synthetic JSON field"))
        val engineStatus = client.callTool("burp_get_rule_engine_status", mapOf("includeDiagnostics" to false))!!
        assertFalse(engineStatus.isError == true, engineStatus.content.toString())
        assertTrue(engineStatus.content.toString().contains("maximumModificationsPerRule"))
        val ruleId = Json.parseToJsonElement((created.content.single() as TextContent).text)
            .jsonObject["id"]!!.jsonPrimitive.content
        live.allowEdits = true
        live.startApprovedSession(60)
        val enabled = client.callTool("burp_enable_interception_rule", mapOf("ruleId" to ruleId))!!
        assertFalse(enabled.isError == true, enabled.content.toString())
        assertTrue(enabled.content.toString().contains("ACTIVE"))
        val stats = client.callTool("burp_get_interception_rule_stats", mapOf("ruleId" to ruleId))!!
        assertFalse(stats.isError == true, stats.content.toString())
        assertTrue(stats.content.toString().contains("remainingModifications"))
        val paused = client.callTool("burp_disable_interception_rule", mapOf("ruleId" to ruleId))!!
        assertFalse(paused.isError == true, paused.content.toString())
        assertTrue(paused.content.toString().contains("PAUSED"))
        val deleted = client.callTool("burp_delete_interception_rule", mapOf("ruleId" to ruleId))!!
        assertFalse(deleted.isError == true, deleted.content.toString())
        live.disable("TEST_CLEANUP")
        live.deactivateUnattendedLocalTestMode("TEST_CLEANUP")
        Unit
    }

    @Test
    fun `eight concurrent read only status calls remain responsive`() = runBlocking {
        val results = coroutineScope {
            (1..8).map {
                async { client.callTool("burp_get_status", mapOf("includeDiagnostics" to false)) }
            }.awaitAll()
        }
        assertEquals(8, results.size)
        results.forEach { assertReportedBuildIdentity(it, "burp_get_status") }
    }

    @Test
    fun `stateless transport rejects SSE and completes repeated MCP clients`() = runBlocking {
        val probe = HttpClient()
        try {
            val get = withTimeout(2_000) {
                probe.get("http://127.0.0.1:$testPort/mcp") {
                    headers.append(io.ktor.http.HttpHeaders.Authorization, "Bearer ${config.bearerToken}")
                    headers.append(io.ktor.http.HttpHeaders.Accept, "text/event-stream")
                }
            }
            assertEquals(HttpStatusCode.MethodNotAllowed, get.status)
            assertEquals("POST", get.headers[io.ktor.http.HttpHeaders.Allow])
        } finally {
            probe.close()
        }

        repeat(10) { index ->
            val sessionClient = TestStreamableHttpMcpClient()
            try {
                withTimeout(5_000) {
                    sessionClient.connectToServer("http://127.0.0.1:${testPort}/mcp", config.bearerToken)
                    val status = sessionClient.callTool("burp_get_status", mapOf("includeDiagnostics" to false))
                    assertReportedBuildIdentity(status, "burp_get_status after session $index")
                }
            } finally {
                withTimeout(5_000) { sessionClient.close() }
            }
        }
    }

    @Test
    fun `stateless listener restarts on the same port after client churn`() = runBlocking {
        repeat(3) {
            val stopped = CompletableDeferred<Unit>()
            serverManager.stop { state ->
                if (state is ServerState.Stopped) stopped.complete(Unit)
                if (state is ServerState.Failed) stopped.completeExceptionally(state.exception)
            }
            withTimeout(10_000) { stopped.await() }
            val started = CompletableDeferred<Unit>()
            serverManager.start(config) { state ->
                if (state is ServerState.Running) started.complete(Unit)
                if (state is ServerState.Failed) started.completeExceptionally(state.exception)
            }
            withTimeout(10_000) { started.await() }
            val freshClient = TestStreamableHttpMcpClient()
            try {
                withTimeout(5_000) {
                    freshClient.connectToServer("http://127.0.0.1:$testPort/mcp", config.bearerToken)
                    freshClient.ping()
                    assertReportedBuildIdentity(freshClient.callTool("burp_get_status", emptyMap()), "restarted server")
                }
            } finally {
                withTimeout(5_000) { freshClient.close() }
            }
        }
    }

    @Test
    fun `one pending approval serializes a second and does not stall MCP health calls`() = runBlocking {
        every { persistedObject.getBoolean("readOnlyMode") } returns false
        config.readOnlyMode = false
        config.addAutoApproveTarget("127.0.0.1:8000")
        live.startApprovedSession(60)
        every { api.scope().isInScope(any()) } returns true

        val request = mockk<burp.api.montoya.http.message.requests.HttpRequest>(relaxed = true)
        every { request.httpService().host() } returns "127.0.0.1"
        every { request.httpService().port() } returns 8000
        every { request.httpService().secure() } returns false
        every { request.url() } returns "http://127.0.0.1:8000/test-cancel"
        every { request.method() } returns "GET"
        assertFalse(config.readOnlyMode)
        assertTrue(live.health().enabled)
        assertTrue(live.authorized(request))
        val ticket = live.queue.offer(
            "request",
            net.portswigger.mcp.intercept.HeldMessage(request, request),
            10_000
        )!!
        val secondTicket = live.queue.offer(
            "request",
            net.portswigger.mcp.intercept.HeldMessage(request, request),
            10_000
        )!!

        mockkObject(net.portswigger.mcp.config.Dialogs)
        val releaseApproval = CompletableDeferred<Unit>()
        try {
            val promptStarted = CompletableDeferred<Unit>()
            coEvery {
                net.portswigger.mcp.config.Dialogs.requestOption(any(), any(), any(), any(), any(), any())
            } coAnswers {
                promptStarted.complete(Unit)
                releaseApproval.await()
                0
            }

            val approval = async {
                client.callTool(
                    "burp_approve_intercepted_request_edit",
                    mapOf("id" to ticket.id, "revision" to 0)
                )
            }
            val promptObserved = withTimeoutOrNull(2_000) {
                promptStarted.await()
                true
            } == true
            if (!promptObserved) {
                val result = withTimeoutOrNull(1_000) { approval.await() }
                val detail = result?.content?.joinToString(" ") { it.toString() }?.take(256)
                val events = net.portswigger.mcp.security.ActivityLog.snapshot().take(8)
                    .joinToString(" | ") { "${it.action}:${it.outcome}:${it.detail}" }
                throw AssertionError("Approval did not reach its local review prompt; completed=${approval.isCompleted} error=${result?.isError} detail=$detail events=$events")
            }

            val simultaneousApproval = withTimeout(1_500) {
                client.callTool(
                    "burp_approve_intercepted_request_edit",
                    mapOf("id" to secondTicket.id, "revision" to 0)
                )
            }
            assertTrue(simultaneousApproval!!.isError == true, "A second concurrent local review must fail closed without opening another prompt")

            val healthClients = (1..8).map { TestStreamableHttpMcpClient() }
            val statuses = try {
                coroutineScope {
                    healthClients.mapIndexed { index, healthClient ->
                        async {
                            withTimeout(3_000) {
                                healthClient.connectToServer(
                                    "http://127.0.0.1:${testPort}/mcp",
                                    config.bearerToken
                                )
                                val status = healthClient.callTool(
                                    "burp_get_status",
                                    mapOf("includeDiagnostics" to false)
                                )
                                assertReportedBuildIdentity(status, "concurrent client $index")
                                status
                            }
                        }
                    }.awaitAll()
                }
            } finally {
                healthClients.forEach { healthClient ->
                    if (healthClient.isConnected()) withTimeout(3_000) { healthClient.close() }
                }
            }
            assertEquals(8, statuses.size)
            statuses.forEach { assertReportedBuildIdentity(it, "burp_get_status") }
            assertFalse(approval.isCompleted, "Health calls must complete while the approval prompt is still pending")
            releaseApproval.complete(Unit)
            assertFalse(approval.await()!!.isError == true)
            assertEquals(0, live.queue.get(ticket.id).approvedRevision)
        } finally {
            releaseApproval.complete(Unit)
            unmockkObject(net.portswigger.mcp.config.Dialogs)
        }
    }

    @Test
    fun `MCP input validation rejects unsafe request modifications`() = runBlocking {
        val result = client.callTool(
            "burp_modify_request",
            mapOf(
                "rawRequest" to "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                "headers" to mapOf("X-Test" to "safe\r\nX-Injected: value")
            )
        )
        assertNotNull(result)
        assertTrue(result!!.isError == true)
    }

    @Test
    fun `server stops gracefully`() = runBlocking {
        val stopped = kotlinx.coroutines.CompletableDeferred<ServerState>()
        serverManager.stop { state ->
            if (state is ServerState.Stopped) stopped.complete(state)
        }
        assertTrue(kotlinx.coroutines.withTimeout(5000) { stopped.await() } is ServerState.Stopped)
    }

    @Test
    fun `live tools reject unknown IDs and withhold captured contents before disclosure`() = runBlocking {
        val missing=client.callTool("burp_get_intercepted_request",mapOf("id" to "unknown"))!!
        assertTrue(missing.isError == true)
        assertTrue(missing.content.toString().contains("unknown"))
        val request=mockk<burp.api.montoya.http.message.requests.HttpRequest>(relaxed=true)
        every { request.httpService().host() } returns "127.0.0.1"
        every { request.httpService().port() } returns 80
        every { request.url() } returns "http://127.0.0.1/"
        every { api.scope().isInScope(any()) } returns true
        every { request.toString() } returns "LOCAL SECRET BODY"
        val ticket=live.queue.offer("request",net.portswigger.mcp.intercept.HeldMessage(request,request),10_000)!!
        val result=client.callTool("burp_get_intercepted_request",mapOf("id" to ticket.id))!!
        assertFalse(result.isError == true)
        assertTrue(result.content.toString().contains("contentDisclosureApproved"))
        assertFalse(result.content.toString().contains("LOCAL SECRET BODY"))
        io.mockk.verify(exactly=0) { request.headers() }
    }

    @Test
    fun `interception diagnostics are read only and payload free`() = runBlocking {
        net.portswigger.mcp.security.ActivityLog.clear()
        net.portswigger.mcp.security.ActivityLog.record("intercept_request", "skipped", "GET 127.0.0.1/test; outside Burp scope")
        val result = client.callTool("burp_get_intercept_diagnostics", mapOf("count" to 10))!!
        assertFalse(result.isError == true)
        val text = result.content.toString()
        assertTrue(text.contains("outside Burp scope"))
        assertTrue(text.contains("heartbeatHealth"))
        assertFalse(text.contains("Cookie:"))
        assertFalse(text.contains("Authorization:"))
    }
}
