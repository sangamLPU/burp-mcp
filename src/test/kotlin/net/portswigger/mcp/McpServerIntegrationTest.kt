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
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.intercept.LiveInterception
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ServerSocket

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
        serverManager.stop {}
        live.close()
    }

    @Test
    fun `server should accept connections and list tools`() = runBlocking {
        try {
            assertTrue(client.isConnected(), "Client should be connected to server")
            
            val tools = client.listTools()
            assertFalse(tools.isEmpty(), "Server should have registered tools")
            assertEquals(70, tools.size, "The Professional MCP catalog must retain all tools, including read-only interception diagnostics")
            assertTrue(tools.any { it.name == "burp_get_intercepted_request" })
            assertTrue(tools.any { it.name == "burp_forward_intercepted_response" })
            assertTrue(tools.any { it.name == "burp_get_intercept_diagnostics" })
            
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
