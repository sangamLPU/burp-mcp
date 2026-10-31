package net.portswigger.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.http.*
import io.mockk.*
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.RequestRateLimiter
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.*
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import net.portswigger.mcp.config.Dialogs

class LiveInterceptionTest {
    private val api=mockk<MontoyaApi>(relaxed=true)
    private val request=mockk<InterceptedRequest>(relaxed=true)
    private val response=mockk<InterceptedResponse>(relaxed=true)
    private val requestHandler=slot<ProxyRequestHandler>();private val responseHandler=slot<ProxyResponseHandler>()
    private val registration=mockk<Registration>(relaxed=true)
    private val pool=Executors.newFixedThreadPool(2)
    private lateinit var live:LiveInterception
    private lateinit var config:McpConfig
    private val requestDropped=mockk<ProxyRequestReceivedAction>();private val responseDropped=mockk<ProxyResponseReceivedAction>()
    @BeforeEach fun setup() {
        val storage=mockk<PersistedObject>(relaxed=true)
        val values=mutableMapOf<String,Any>("readOnlyMode" to false,"_autoApproveTargets" to "localhost:8000","bearerToken" to "test")
        every { storage.getBoolean(any()) } answers { values[firstArg()] as? Boolean }
        every { storage.getString(any()) } answers { values[firstArg()] as? String }
        every { storage.getInteger(any()) } answers { values[firstArg()] as? Int }
        every { storage.setBoolean(any(),any()) } answers { values[firstArg()]=secondArg<Boolean>() }
        every { storage.setInteger(any(),any()) } answers { values[firstArg()]=secondArg<Int>() }
        config=McpConfig(storage,api.logging())
        every { request.httpService().host() } returns "localhost"
        every { request.httpService().port() } returns 8000
        every { request.url() } returns "http://localhost:8000/test"
        every { request.method() } returns "GET"
        every { request.path() } returns "/test?token=query-secret&item=private-value"
        every { request.toByteArray().length() } returns 50
        every { response.toByteArray().length() } returns 50
        every { response.initiatingRequest() } returns request
        every { api.scope().isInScope(any()) } returns true
        every { api.proxy().registerRequestHandler(capture(requestHandler)) } returns registration
        every { api.proxy().registerResponseHandler(capture(responseHandler)) } returns registration
        mockkStatic(ProxyRequestReceivedAction::class);mockkStatic(ProxyResponseReceivedAction::class)
        every { ProxyRequestReceivedAction.drop() } returns requestDropped
        every { ProxyResponseReceivedAction.drop() } returns responseDropped
        every { ProxyRequestReceivedAction.continueWith(any<HttpRequest>()) } answers { mockk<ProxyRequestReceivedAction>().also { action -> every { action.request() } returns firstArg() } }
        every { ProxyRequestReceivedAction.doNotIntercept(any<HttpRequest>()) } answers { val sent=firstArg<HttpRequest>();mockk<ProxyRequestReceivedAction>().also { action -> every { action.request() } returns sent } }
        every { ProxyResponseReceivedAction.doNotIntercept(any<HttpResponse>()) } answers { val sent=firstArg<HttpResponse>();mockk<ProxyResponseReceivedAction>().also { action -> every { action.response() } returns sent } }
        live=LiveInterception(api,config);live.install();live.startApprovedSession(60);RequestRateLimiter.resetForTests()
    }
    @AfterEach fun cleanup() { live.close();pool.shutdownNow();unmockkStatic(ProxyRequestReceivedAction::class);unmockkStatic(ProxyResponseReceivedAction::class) }
    private fun pending(kind:String):DecisionQueue.Ticket<HeldMessage> {
        val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(2)
        while(System.nanoTime()<deadline) { live.queue.list(kind).firstOrNull()?.let { return it };Thread.yield() }
        error("Callback failed to enter pending queue")
    }
    @Test fun `request callback stays pending and forwards only the approved patch`() {
        val result=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        val t=pending("request");assertFalse(result.isDone)
        val edited=mockk<HttpRequest>(relaxed=true)
        every { edited.httpService() } returns request.httpService();every { edited.url() } returns request.url()
        every { edited.toByteArray().length() } returns 50
        every { request.withHeader("X-Test","changed") } returns edited
        assertThrows(IllegalStateException::class.java) { live.propose(t.id,"request",0,mapOf("X-Test" to "changed"),emptyList(),null,null) }
        live.allowEdits=true
        live.propose(t.id,"request",0,mapOf("X-Test" to "changed"),emptyList(),null,null)
        assertThrows(IllegalStateException::class.java) { live.forward(t.id,"request",1) }
        live.approveLocally(t.id,"request",1);live.forward(t.id,"request",1)
        assertSame(edited,result.get(2,TimeUnit.SECONDS).request())
        assertThrows(IllegalStateException::class.java) { live.forward(t.id,"request",1) }
    }
    @Test fun `response patch reaches downstream callback and drop is final`() {
        val result=pool.submit<ProxyResponseReceivedAction> { responseHandler.captured.handleResponseReceived(response) }
        val t=pending("response");assertFalse(result.isDone)
        val edited=mockk<HttpResponse>(relaxed=true);every { edited.toByteArray().length() } returns 50
        every { response.hasHeader("X-Test") } returns false
        every { response.withAddedHeader("X-Test","value") } returns edited
        every { edited.withBody("replacement") } returns edited
        live.allowEdits=true;live.propose(t.id,"response",0,mapOf("X-Test" to "value"),emptyList(),"replacement",null)
        live.approveLocally(t.id,"response",1);live.forward(t.id,"response",1)
        assertSame(edited,result.get(2,TimeUnit.SECONDS).response())
        verify(exactly=1) { edited.withBody("replacement") }
        val dropped=pool.submit<ProxyResponseReceivedAction> { responseHandler.captured.handleResponseReceived(response) }
        live.queue.drop(pending("response").id);assertSame(responseDropped,dropped.get(2,TimeUnit.SECONDS))
    }
    @Test fun `scope revocation drops already held request`() {
        val result=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        val t=pending("request");every { api.scope().isInScope(any()) } returns false
        assertThrows(IllegalStateException::class.java) { live.snapshot(t.id,"request") }
        assertSame(requestDropped,result.get(2,TimeUnit.SECONDS))
    }
    @Test fun `missed internal heartbeat and unload release callbacks with drop`() {
        val result=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) };pending("request")
        live.heartbeatTick(System.nanoTime()+TimeUnit.SECONDS.toNanos(16))
        assertFalse(live.enabled);assertSame(requestDropped,result.get(2,TimeUnit.SECONDS))
        live.startApprovedSession(60)
        val second=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) };pending("request");live.close()
        assertSame(requestDropped,second.get(2,TimeUnit.SECONDS))
        assertEquals("UNLOADED", live.health().sessionEndReason)
        assertEquals("STOPPED", live.health().heartbeatHealth)
        verify(atLeast=1) { registration.deregister() }
    }

    @Test fun `automatic heartbeat keeps approved session healthy without MCP polling`() {
        val initialHealth = live.health()
        val startedAt = initialHealth.lastHeartbeatAtEpochMillis
        val fixedSessionExpiry = initialHealth.sessionExpiresAtEpochMillis
        live.touch()
        assertEquals(fixedSessionExpiry, live.health().sessionExpiresAtEpochMillis, "Client activity must not extend the approved session")
        Thread.sleep(TimeUnit.SECONDS.toMillis(4))
        val health = live.health()
        assertTrue(live.enabled)
        assertEquals("HEALTHY", health.heartbeatHealth)
        assertTrue(health.lastHeartbeatAtEpochMillis!! > startedAt!!)
        assertTrue(health.leaseRemainingMillis > TimeUnit.SECONDS.toMillis(10))
    }

    @Test fun `pending metadata exposes safe request identity without query values`() {
        val metadata = requestMetadata(request)
        assertEquals("GET", metadata.method)
        assertEquals("localhost", metadata.hostname)
        assertEquals("/test?[query redacted]", metadata.urlPath)
        assertFalse(metadata.urlPath.contains("query-secret"))
        assertFalse(metadata.urlPath.contains("private-value"))
    }

    @Test fun `remote drop waits for explicit local confirmation`() = runBlocking {
        mockkObject(Dialogs)
        val localDecision = CompletableDeferred<Int>()
        coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } coAnswers {
            localDecision.await()
        }
        try {
            val callback = pool.submit<ProxyRequestReceivedAction> {
                requestHandler.captured.handleRequestReceived(request)
            }
            val ticket = pending("request")
            val drop = async { live.dropWithLocalApproval(ticket.id, "request") }
            delay(25)
            assertFalse(callback.isDone, "the callback must remain held until a local decision")
            assertEquals(ticket.id, live.queue.get(ticket.id).id)
            localDecision.complete(0)
            drop.await()
            assertSame(requestDropped, callback.get(2, TimeUnit.SECONDS))
            assertTrue(net.portswigger.mcp.security.ActivityLog.snapshot().any {
                it.action == "intercept_drop" && it.detail.contains(ticket.id)
            })
        } finally {
            localDecision.complete(1)
            unmockkObject(Dialogs)
        }
    }

    @Test fun `disclosure request returns immediately and keeps the same ID until local approval`() = runBlocking {
        mockkObject(Dialogs)
        val promptShown = CompletableDeferred<Unit>()
        val allowDisclosure = CompletableDeferred<Int>()
        coEvery { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) } coAnswers {
            promptShown.complete(Unit)
            allowDisclosure.await()
        }
        try {
            val callback = pool.submit<ProxyRequestReceivedAction> {
                requestHandler.captured.handleRequestReceived(request)
            }
            val ticket = pending("request")
            assertEquals("PENDING", live.requestDisclosure(ticket.id, "request", 0))
            withTimeout(2_000) { promptShown.await() }

            val visible = live.queue.get(ticket.id)
            assertEquals(ticket.id, visible.id)
            assertEquals("PENDING", visible.disclosureStatus)
            assertTrue(visible.disclosedRevision == null)
            assertFalse(callback.isDone)
            assertThrows(IllegalStateException::class.java) { live.queue.forward(ticket.id, 0) }

            assertEquals("PENDING", live.requestDisclosure(ticket.id, "request", 0))
            coVerify(exactly = 1) { Dialogs.requestOption(any(), any(), any(), any(), any(), any()) }
            allowDisclosure.complete(0)
            withTimeout(2_000) {
                while (live.queue.get(ticket.id).disclosureStatus != "APPROVED") delay(10)
            }
            val approvedDisclosure = live.queue.get(ticket.id)
            assertEquals(ticket.id, approvedDisclosure.id)
            assertEquals(0, approvedDisclosure.disclosedRevision)
            assertTrue(approvedDisclosure.approvedRevision == null)
            assertFalse(callback.isDone)
        } finally {
            allowDisclosure.complete(1)
            unmockkObject(Dialogs)
        }
    }

    @Test fun `configured per-message timeout persists and stays bounded`() {
        live.setTimeout(LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS)
        assertEquals(LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS, live.timeoutSeconds)
        assertEquals(LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS, config.interceptionTimeoutSeconds)
        assertThrows(IllegalArgumentException::class.java) { live.setTimeout(LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS + 1) }
        assertEquals(LiveInterception.MAX_MESSAGE_TIMEOUT_SECONDS, live.timeoutSeconds)
    }

    @Test fun `session lifetime is capped and expiry drops pending traffic`() {
        assertThrows(IllegalArgumentException::class.java) {
            live.startApprovedSession(LiveInterception.MAX_SESSION_LIFETIME_SECONDS + 1)
        }
        val result = pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        pending("request")
        live.heartbeatTick(System.nanoTime() + TimeUnit.SECONDS.toNanos(61))
        assertFalse(live.enabled)
        assertEquals("SESSION_EXPIRED", live.health().sessionEndReason)
        assertSame(requestDropped, result.get(2, TimeUnit.SECONDS))
    }

    @Test fun `explicit disable stops heartbeat and drops held traffic`() {
        val result = pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        pending("request")
        live.disable()
        assertSame(requestDropped, result.get(2, TimeUnit.SECONDS))
        val health = live.health()
        assertFalse(health.enabled)
        assertEquals("STOPPED", health.heartbeatHealth)
        assertEquals("DISABLED", health.sessionEndReason)
        assertTrue(health.lastHeartbeatAtEpochMillis == null)
        live.heartbeatTick(System.nanoTime() + TimeUnit.SECONDS.toNanos(5))
        assertTrue(live.health().lastHeartbeatAtEpochMillis == null)
    }

    @Test fun `off scope requests are never held`() {
        net.portswigger.mcp.security.ActivityLog.clear()
        every { api.scope().isInScope(any()) } returns false
        assertSame(request,requestHandler.captured.handleRequestReceived(request).request())
        assertTrue(live.queue.list("request").isEmpty())
        assertTrue(net.portswigger.mcp.security.ActivityLog.snapshot().any {
            it.action == "intercept_request" && it.outcome == "skipped" && it.detail.contains("outside Burp scope")
        })
    }

    @Test fun `eligible GET messages on the UI thread and oversized messages are dropped with diagnostics`() {
        net.portswigger.mcp.security.ActivityLog.clear()
        var uiAction: ProxyRequestReceivedAction? = null
        javax.swing.SwingUtilities.invokeAndWait {
            uiAction = requestHandler.captured.handleRequestReceived(request)
        }
        assertSame(requestDropped, uiAction)
        assertTrue(net.portswigger.mcp.security.ActivityLog.snapshot().any {
            it.action == "intercept_request" && it.outcome == "dropped" && it.detail.contains("UI thread")
        })

        every { request.toByteArray().length() } returns net.portswigger.mcp.security.SafeContent.MAX_REQUEST_BYTES + 1
        val oversized = requestHandler.captured.handleRequestReceived(request)
        assertSame(requestDropped, oversized)
        assertTrue(live.queue.list("request").isEmpty())
        assertTrue(net.portswigger.mcp.security.ActivityLog.snapshot().any {
            it.action == "intercept_request" && it.outcome == "dropped" && it.detail.contains("interception limit")
        })
    }
    @Test fun `disabling authentication prevents disclosure and cancels held traffic`() {
        val result=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
        val ticket=pending("request");config.requireBearerToken=false
        assertThrows(IllegalStateException::class.java) { live.snapshot(ticket.id,"request") }
        assertFalse(live.enabled);assertSame(requestDropped,result.get(2,TimeUnit.SECONDS))
    }
    @Test fun `emergency cancellation dismisses a pending human approval without forwarding`() = runBlocking {
        mockkObject(Dialogs)
        val entered=CompletableDeferred<Unit>()
        coEvery { Dialogs.requestOption(any(),any(),any(),any(),any(),any()) } coAnswers { entered.complete(Unit);awaitCancellation() }
        try {
            val callback=pool.submit<ProxyRequestReceivedAction> { requestHandler.captured.handleRequestReceived(request) }
            val ticket=pending("request")
            val review=async { live.requestApproval(ticket.id,"request",0) }
            withTimeout(2000) { entered.await() }
            live.cancel()
            val reviewFailure = withTimeout(2000) { runCatching { review.await() }.exceptionOrNull() }
            assertTrue(reviewFailure is CancellationException)
            assertSame(requestDropped,callback.get(2,TimeUnit.SECONDS))
        } finally { unmockkObject(Dialogs) }
    }
}
