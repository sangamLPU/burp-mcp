package net.portswigger.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.HttpMessage
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.http.*
import net.portswigger.mcp.config.Dialogs
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.security.*
import net.portswigger.mcp.tools.isAuthorizedRequest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap
import javax.swing.SwingUtilities
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import java.util.concurrent.Semaphore

data class HeldMessage(val message: HttpMessage, val request: HttpRequest)
private data class CaptureSkip(val reason: String, val mustDrop: Boolean)

data class InterceptionHealth(
    val enabled: Boolean,
    val heartbeatHealth: String,
    val sessionLifetimeSeconds: Int,
    val heartbeatIntervalSeconds: Int,
    val sessionRemainingMillis: Long,
    val sessionExpiresAtEpochMillis: Long?,
    val leaseRemainingMillis: Long,
    val leaseExpiresAtEpochMillis: Long?,
    val lastHeartbeatAtEpochMillis: Long?,
    val sessionEndReason: String,
    val pendingRequests: Int,
    val pendingResponses: Int,
    val queueCapacity: Int
)

class LiveInterception(private val api: MontoyaApi, val config: McpConfig) : AutoCloseable {
    companion object {
        const val CLIENT_LEASE_SECONDS = 15
        const val HEARTBEAT_INTERVAL_SECONDS = 3
        const val DEFAULT_SESSION_LIFETIME_SECONDS = 300
        const val MIN_SESSION_LIFETIME_SECONDS = 60
        const val MAX_SESSION_LIFETIME_SECONDS = 600
        const val DEFAULT_MESSAGE_TIMEOUT_SECONDS = 60
        const val MIN_MESSAGE_TIMEOUT_SECONDS = 5
        const val MAX_MESSAGE_TIMEOUT_SECONDS = 120
        const val QUEUE_CAPACITY = 8
    }

    val queue = DecisionQueue<HeldMessage>()
    @Volatile var enabled = false; private set
    @Volatile var allowEdits = false
    @Volatile var timeoutSeconds = config.interceptionTimeoutSeconds; private set
    @Volatile var configuredSessionLifetimeSeconds = DEFAULT_SESSION_LIFETIME_SECONDS; private set
    @Volatile private var lastClientNanos = System.nanoTime()
    @Volatile private var lastHeartbeatNanos: Long? = null
    @Volatile private var nextHeartbeatNanos: Long? = null
    @Volatile private var sessionDeadlineNanos: Long? = null
    @Volatile private var sessionDeadlineEpochMillis: Long? = null
    @Volatile private var lastHeartbeatEpochMillis: Long? = null
    @Volatile private var heartbeatHealth = "STOPPED"
    @Volatile private var sessionEndReason = "NONE"
    @Volatile private var closed = false
    private val reviewPermit = Semaphore(1)
    private val reviewJobs = ConcurrentHashMap<String, Job>()
    private val disclosureJobs = ConcurrentHashMap<String, Job>()
    private val disclosureScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val registrations = mutableListOf<Registration>()
    private val timer = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "burp-mcp-interception-expiry").apply { isDaemon = true } }

    fun install() {
        registrations += api.proxy().registerRequestHandler(object : ProxyRequestHandler {
            override fun handleRequestReceived(request: InterceptedRequest): ProxyRequestReceivedAction {
                val skip = captureSkipReason(request, request)
                if (skip != null) {
                    logCaptureSkip("request", request, skip)
                    return if (skip.mustDrop) ProxyRequestReceivedAction.drop()
                        else ProxyRequestReceivedAction.continueWith(request)
                }
                val result = runCatching { hold("request", HeldMessage(request, request)) }.getOrElse {
                    ActivityLog.record("intercept_request", "dropped", it.javaClass.simpleName); null
                }
                return if (result == null) ProxyRequestReceivedAction.drop()
                    else ProxyRequestReceivedAction.doNotIntercept(result.message as HttpRequest)
            }
            override fun handleRequestToBeSent(request: InterceptedRequest) = ProxyRequestToBeSentAction.continueWith(request)
        })
        registrations += api.proxy().registerResponseHandler(object : ProxyResponseHandler {
            override fun handleResponseReceived(response: InterceptedResponse): ProxyResponseReceivedAction {
                val request = response.initiatingRequest()
                val skip = captureSkipReason(response, request)
                if (skip != null) {
                    logCaptureSkip("response", request, skip)
                    return if (skip.mustDrop) ProxyResponseReceivedAction.drop()
                        else ProxyResponseReceivedAction.continueWith(response)
                }
                val result = runCatching { hold("response", HeldMessage(response, request)) }.getOrElse {
                    ActivityLog.record("intercept_response", "dropped", it.javaClass.simpleName); null
                }
                return if (result == null) ProxyResponseReceivedAction.drop()
                    else ProxyResponseReceivedAction.doNotIntercept(result.message as HttpResponse)
            }
            override fun handleResponseToBeSent(response: InterceptedResponse) = ProxyResponseToBeSentAction.continueWith(response)
        })
        timer.scheduleAtFixedRate({
            runCatching {
                queue.expire()
                heartbeatTick()
            }.onFailure { ActivityLog.record("intercept_expiry", "error", it.javaClass.simpleName) }
        }, 1, 1, TimeUnit.SECONDS)
    }

    @Synchronized fun touch() { lastClientNanos = System.nanoTime() }

    @Synchronized fun setConfiguredSessionLifetime(seconds: Int) {
        require(seconds in MIN_SESSION_LIFETIME_SECONDS..MAX_SESSION_LIFETIME_SECONDS) {
            "Session lifetime must be between $MIN_SESSION_LIFETIME_SECONDS and $MAX_SESSION_LIFETIME_SECONDS seconds"
        }
        configuredSessionLifetimeSeconds = seconds
    }

    fun validateSessionLifetime(seconds: Int) {
        require(seconds in MIN_SESSION_LIFETIME_SECONDS..MAX_SESSION_LIFETIME_SECONDS) {
            "Session lifetime must be between $MIN_SESSION_LIFETIME_SECONDS and $MAX_SESSION_LIFETIME_SECONDS seconds"
        }
    }

    /** Call only after a local Burp confirmation or an explicit local UI confirmation. */
    @Synchronized fun startApprovedSession(seconds: Int = configuredSessionLifetimeSeconds) {
        check(!closed) { "Extension has unloaded" }
        check(config.requireBearerToken) { "Enable MCP bearer authentication before live interception" }
        validateSessionLifetime(seconds)
        val nowNanos = System.nanoTime()
        val nowMillis = System.currentTimeMillis()
        val durationNanos = TimeUnit.SECONDS.toNanos(seconds.toLong())
        configuredSessionLifetimeSeconds = seconds
        enabled = true
        sessionDeadlineNanos = nowNanos + durationNanos
        sessionDeadlineEpochMillis = nowMillis + TimeUnit.NANOSECONDS.toMillis(durationNanos)
        lastHeartbeatNanos = nowNanos
        nextHeartbeatNanos = nowNanos + TimeUnit.SECONDS.toNanos(HEARTBEAT_INTERVAL_SECONDS.toLong())
        lastHeartbeatEpochMillis = nowMillis
        lastClientNanos = nowNanos
        heartbeatHealth = "HEALTHY"
        sessionEndReason = "NONE"
        ActivityLog.record("intercept_session", "approved", "lifetime=${seconds}s; heartbeat=${HEARTBEAT_INTERVAL_SECONDS}s")
    }

    fun setTimeout(seconds: Int) {
        require(seconds in MIN_MESSAGE_TIMEOUT_SECONDS..MAX_MESSAGE_TIMEOUT_SECONDS) {
            "Per-message timeout must be between $MIN_MESSAGE_TIMEOUT_SECONDS and $MAX_MESSAGE_TIMEOUT_SECONDS seconds"
        }
        config.interceptionTimeoutSeconds = seconds
        timeoutSeconds = seconds
    }

    @Synchronized fun disable(reason: String = "DISABLED") { endSession(reason) }

    @Synchronized fun cancel(reason: String = "CANCELLED") {
        endSession(reason)
    }

    @Synchronized internal fun heartbeatTick(nowNanos: Long = System.nanoTime()) {
        if (!enabled) return
        if (!config.requireBearerToken) { endSession("AUTHENTICATION_DISABLED"); return }
        val deadline = sessionDeadlineNanos
        if (deadline == null || nowNanos >= deadline) { endSession("SESSION_EXPIRED"); return }

        val last = lastHeartbeatNanos ?: nowNanos
        if (nowNanos - last >= TimeUnit.SECONDS.toNanos(CLIENT_LEASE_SECONDS.toLong())) {
            endSession("HEARTBEAT_MISSED")
            return
        }
        val next = nextHeartbeatNanos ?: nowNanos
        if (nowNanos >= next) {
            lastHeartbeatNanos = nowNanos
            lastHeartbeatEpochMillis = System.currentTimeMillis()
            lastClientNanos = nowNanos
            nextHeartbeatNanos = nowNanos + TimeUnit.SECONDS.toNanos(HEARTBEAT_INTERVAL_SECONDS.toLong())
            heartbeatHealth = "HEALTHY"
        } else if (nowNanos - last > TimeUnit.SECONDS.toNanos(HEARTBEAT_INTERVAL_SECONDS * 2L)) {
            heartbeatHealth = "DEGRADED"
        }
    }

    @Synchronized fun health(nowNanos: Long = System.nanoTime()): InterceptionHealth {
        val sessionDeadline = sessionDeadlineNanos
        val leaseExpiry = if (enabled) lastClientNanos + TimeUnit.SECONDS.toNanos(CLIENT_LEASE_SECONDS.toLong()) else null
        val sessionRemaining = sessionDeadline?.let { (it - nowNanos).coerceAtLeast(0) / 1_000_000 } ?: 0L
        val leaseRemaining = leaseExpiry?.let { (it - nowNanos).coerceAtLeast(0) / 1_000_000 } ?: 0L
        val nowMillis = System.currentTimeMillis()
        fun epochFor(deadline: Long?): Long? = deadline?.let { nowMillis + ((it - nowNanos) / 1_000_000).coerceAtLeast(0) }
        return InterceptionHealth(
            enabled = enabled,
            heartbeatHealth = heartbeatHealth,
            sessionLifetimeSeconds = configuredSessionLifetimeSeconds,
            heartbeatIntervalSeconds = HEARTBEAT_INTERVAL_SECONDS,
            sessionRemainingMillis = sessionRemaining,
            sessionExpiresAtEpochMillis = if (enabled) sessionDeadlineEpochMillis else null,
            leaseRemainingMillis = leaseRemaining,
            leaseExpiresAtEpochMillis = epochFor(leaseExpiry),
            lastHeartbeatAtEpochMillis = if (enabled) lastHeartbeatEpochMillis else null,
            sessionEndReason = sessionEndReason,
            pendingRequests = queue.list("request").size,
            pendingResponses = queue.list("response").size,
            queueCapacity = QUEUE_CAPACITY
        )
    }

    private fun endSession(reason: String) {
        val wasActive = enabled
        enabled = false
        heartbeatHealth = when (reason) {
            "SESSION_EXPIRED", "HEARTBEAT_MISSED" -> "EXPIRED"
            else -> "STOPPED"
        }
        sessionEndReason = reason
        sessionDeadlineNanos = null
        sessionDeadlineEpochMillis = null
        lastHeartbeatNanos = null
        nextHeartbeatNanos = null
        lastHeartbeatEpochMillis = null
        queue.cancelAll(reason)
        reviewJobs.values.toList().forEach { it.cancel(CancellationException("Interception session ended: $reason")) }
        reviewJobs.clear()
        disclosureJobs.values.toList().forEach { it.cancel(CancellationException("Interception session ended: $reason")) }
        disclosureJobs.clear()
        if (wasActive) ActivityLog.record("intercept_session", "ended", reason)
    }
    fun authorized(request: HttpRequest) = runCatching { isAuthorizedRequest(request, api, config) }.getOrDefault(false)

    private fun captureSkipReason(message: HttpMessage, request: HttpRequest): CaptureSkip? {
        if (!enabled) return CaptureSkip("live interception session is disabled", mustDrop = false)
        if (closed) return CaptureSkip("extension is unloading", mustDrop = false)
        authorizationSkipReason(request)?.let { return CaptureSkip(it, mustDrop = false) }
        if (SwingUtilities.isEventDispatchThread()) return CaptureSkip("Proxy callback is on Burp's UI thread; dropped to avoid bypassing local review", mustDrop = true)
        val messageBytes = runCatching { message.toByteArray().length() }.getOrNull()
            ?: return CaptureSkip("message size could not be read safely; dropped because it cannot enter bounded review", mustDrop = true)
        if (messageBytes > SafeContent.MAX_REQUEST_BYTES) {
            return CaptureSkip("message exceeds the ${SafeContent.MAX_REQUEST_BYTES}-byte interception limit; dropped because it cannot enter bounded review", mustDrop = true)
        }
        return null
    }

    private fun authorizationSkipReason(request: HttpRequest): String? {
        val service = runCatching { request.httpService() }.getOrNull()
            ?: return "HTTP service unavailable"
        if (!HttpRequestSecurity.isAllowedByHostAllowlist(service.host(), service.port(), config)) return "host is not in the explicit allowlist"
        val url = runCatching { request.url() }.getOrNull()
            ?: return "request URL unavailable"
        if (!urlMatchesHttpService(url, service.host(), service.port())) return "URL does not match the HTTP service"
        if (!runCatching { api.scope().isInScope(url) }.getOrDefault(false)) return "target is outside Burp scope"
        return null
    }

    private fun logCaptureSkip(kind: String, request: HttpRequest, skip: CaptureSkip) {
        val metadata = requestMetadata(request)
        ActivityLog.record("intercept_$kind", if (skip.mustDrop) "dropped" else "skipped",
            "${metadata.method} ${metadata.hostname}${metadata.urlPath}; ${skip.reason}")
    }

    private fun hold(kind: String, value: HeldMessage): HeldMessage? {
        val ticket = synchronized(this) {
            if (!enabled || closed) {
                ActivityLog.record("intercept_capture", "dropped", "session ended before queue capture")
                return null
            }
            queue.offer(kind, value, timeoutSeconds * 1000L)
        }
        if (ticket == null) { ActivityLog.record("intercept_capture", "dropped", "queue capacity reached"); return null }
        val metadata = requestMetadata(value.request)
        ActivityLog.record("intercept_$kind", "captured", "id=${ticket.id} ${metadata.method} ${metadata.hostname}${metadata.urlPath}")
        val result = queue.await(ticket) ?: return null
        // Scope and allowlist can change while the callback is waiting.
        if (!enabled || closed || !authorized(result.request) || (result.message !== value.message && (config.readOnlyMode || !allowEdits))) {
            ActivityLog.record("intercept_release", "dropped", "authorization or interception policy changed"); return null
        }
        return result
    }

    fun snapshot(id: String, kind: String): DecisionQueue.Ticket<HeldMessage> {
        if (!config.requireBearerToken) { cancel("AUTHENTICATION_DISABLED"); error("Live interception requires bearer authentication") }
        val ticket = queue.get(id)
        check(ticket.kind == kind) { "Message has the wrong direction" }
        if (!authorized(ticket.original.request)) { queue.drop(id); error("Target authorization changed; message dropped") }
        return ticket
    }

    fun propose(id: String, kind: String, revision: Int, headers: Map<String, String>, removeHeaders: List<String>, body: String?, path: String?): Int {
        check(allowEdits && !config.readOnlyMode) { "Enable live edits locally and disable read-only mode first" }
        val ticket = snapshot(id, kind)
        require(headers.size + removeHeaders.size <= 50)
        val forbidden = setOf("host", "content-length", "transfer-encoding", "connection", "upgrade")
        (headers.keys + removeHeaders).forEach {
            require(it.matches(Regex("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")) && it.lowercase() !in forbidden) { "Invalid or protected header" }
        }
        require(headers.values.all { it.length <= 8192 && '\r' !in it && '\n' !in it })
        require(body == null || body.toByteArray().size <= 65_536)
        val encoding=ticket.original.message.headerValue("Content-Encoding").orEmpty()
        require(body==null || encoding.isBlank() || encoding.equals("identity",true)) { "Text body replacement of compressed messages is unsupported" }
        require(path == null || (kind == "request" && path.startsWith("/") && !path.startsWith("//") && path.length <= 8192 && path.none { it.isWhitespace() }))
        // Patches always start from the original so omitted/redacted credentials are preserved locally.
        var message = ticket.original.message
        when (message) {
            is HttpRequest -> {
                var edited: HttpRequest = message
                removeHeaders.forEach { edited = edited.withRemovedHeader(it) }
                headers.forEach { (k,v) -> edited = edited.withHeader(k,v) }
                if (body != null) edited = edited.withBody(body)
                if (path != null) edited = edited.withPath(path)
                check(authorized(edited)) { "Proposed request is outside scope or its authorized service" }
                message = edited
            }
            is HttpResponse -> {
                var edited: HttpResponse = message
                removeHeaders.forEach { edited = edited.withRemovedHeader(it) }
                headers.forEach { (k,v) -> edited = if (edited.hasHeader(k)) edited.withUpdatedHeader(k,v) else edited.withAddedHeader(k,v) }
                if (body != null) edited = edited.withBody(body)
                message = edited
            }
        }
        require(message.toByteArray().length() <= SafeContent.MAX_REQUEST_BYTES)
        return queue.propose(id, revision, HeldMessage(message, if (message is HttpRequest) message else ticket.original.request))
    }

    fun localReview(ticket: DecisionQueue.Ticket<HeldMessage>): String =
        "Message ${ticket.id}, ${ticket.kind}, revision ${ticket.revision}\n\nORIGINAL (local sensitive data)\n${ticket.original.message}\n\nPROPOSED\n${(ticket.proposed ?: ticket.original).message}"

    private suspend fun review(
        ticket: DecisionQueue.Ticket<HeldMessage>,
        message: String,
        options: Array<String>,
        title: String,
        requestContent: String? = localReview(ticket)
    ): Boolean {
        check(reviewPermit.tryAcquire()) { "Another live message is already under human review" }
        val job = currentCoroutineContext()[Job]
        if (job != null) reviewJobs[ticket.id] = job
        try {
            return withTimeout(((ticket.deadline-System.nanoTime())/1_000_000).coerceAtLeast(1)) {
                check(enabled && !closed) { "Interception was cancelled" }
                // Plain text preserves both messages exactly; do not parse the combined review as a request editor.
                Dialogs.requestOption(findBurpFrame(),message,options,requestContent,title=title)==0
            }
        } finally {
            if (job != null) reviewJobs.remove(ticket.id, job)
            reviewPermit.release()
        }
    }

    suspend fun requestApproval(id: String, kind: String, revision: Int) {
        check(!config.readOnlyMode) { "Read-only mode blocks forwarding approvals" }
        val ticket = snapshot(id, kind)
        check(ticket.revision == revision)
        ActivityLog.record("intercept_approval", "prompted", "${ticket.kind} ${ticket.id} revision=$revision")
        val metadata = requestMetadata(ticket.original.request)
        val approved = review(ticket,
            "Review this exact live ${ticket.kind} revision locally. Approve forwarding once? The AI cannot approve it.\n\n" +
                "Request ID: ${ticket.id}\nTarget: ${metadata.hostname}\n${metadata.method} ${metadata.urlPath}\n" +
                "${((ticket.deadline - System.nanoTime()).coerceAtLeast(0) / 1_000_000) / 1000}s hold time remains.",
            arrayOf("Approve once", "Deny"),
            "Approve live request forwarding")
        if (!approved) { ActivityLog.record("intercept_approve", "denied", id); error("User denied approval") }
        approveLocally(id, kind, revision)
    }
    suspend fun dropWithLocalApproval(id: String, kind: String) {
        check(!config.readOnlyMode) { "Read-only mode blocks dropping intercepted messages" }
        val ticket = snapshot(id, kind)
        val metadata = requestMetadata(ticket.original.request)
        val remaining = ((ticket.deadline - System.nanoTime()).coerceAtLeast(0) / 1_000_000) / 1000
        ActivityLog.record("intercept_drop_approval", "prompted", "${ticket.kind} ${ticket.id} revision=${ticket.revision}")
        val approved = review(
            ticket,
            "An MCP client requested that this held ${ticket.kind} be dropped. Confirm this exact message?\n\n" +
                "Request ID: ${ticket.id}\nTarget: ${metadata.hostname}\n${metadata.method} ${metadata.urlPath}\n" +
                "$remaining seconds hold time remain. Dropping a response cannot undo the upstream request.",
            arrayOf("Drop this message", "Keep pending"),
            "Approve intercepted message drop",
            requestContent = null
        )
        if (!approved) {
            ActivityLog.record("intercept_drop_approval", "denied", "${ticket.kind} ${ticket.id} revision=${ticket.revision}")
            error("User denied dropping intercepted message")
        }
        val current = snapshot(id, kind)
        check(current.revision == ticket.revision) { "Message revision changed during drop approval" }
        queue.drop(id)
    }
    fun requestDisclosure(id:String,kind:String,revision:Int): String {
        val ticket=snapshot(id,kind)
        check(ticket.revision==revision)
        val request = queue.beginDisclosureRequest(id, revision)
        if (!request.shouldPrompt) return request.status

        val job = disclosureScope.launch(start = CoroutineStart.LAZY) {
            try {
                val metadata = requestMetadata(ticket.original.request)
                val approved = review(
                    ticket,
                    "Allow this exact request revision to be sent to the external model as a redacted preview?\n\n" +
                        "Request ID: ${ticket.id}\nTarget: ${metadata.hostname}\n${metadata.method} ${metadata.urlPath}\n" +
                        "The preview includes headers and a bounded body. Common credentials are redacted, but application-specific secrets may remain. Review the LOCAL raw content first.",
                    arrayOf("Share redacted preview once", "Deny"),
                    "Approve request disclosure"
                )
                if (approved) {
                    snapshot(id, kind)
                    queue.completeDisclosureRequest(id, revision, "APPROVED")
                } else {
                    queue.completeDisclosureRequest(id, revision, "DENIED")
                }
            } catch (_: TimeoutCancellationException) {
                queue.completeDisclosureRequest(id, revision, "EXPIRED")
                ActivityLog.record("intercept_disclosure", "expired", "$id revision=$revision")
            } catch (error: CancellationException) {
                queue.completeDisclosureRequest(id, revision, "CANCELLED")
                throw error
            } catch (error: Exception) {
                val busy = error.message?.contains("already under human review", ignoreCase = true) == true
                queue.completeDisclosureRequest(id, revision, if (busy) "BUSY" else "ERROR")
                if (!busy) ActivityLog.record("intercept_disclosure", "error", "$id ${error.javaClass.simpleName}")
            }
        }
        disclosureJobs[id] = job
        job.invokeOnCompletion { disclosureJobs.remove(id, job) }
        job.start()
        return "PENDING"
    }
    fun approveLocally(id: String, kind: String, revision: Int) {
        val ticket = snapshot(id, kind)
        check(!config.readOnlyMode && (ticket.proposed == null || allowEdits)) { "Read-only mode or edit policy blocks approval" }
        queue.approve(id, revision)
    }
    fun forward(id: String, kind: String, revision: Int) {
        val ticket = snapshot(id, kind)
        check(!config.readOnlyMode && (ticket.proposed == null || allowEdits))
        check(authorized((ticket.proposed ?: ticket.original).request))
        check(RequestRateLimiter.tryAcquire()) { "Request rate limit exceeded" }
        queue.forward(id, revision)
    }
    override fun close() {
        synchronized(this) { closed = true; endSession("UNLOADED") }
        disclosureScope.cancel()
        timer.shutdownNow()
        registrations.forEach { runCatching { it.deregister() } }
        registrations.clear()
    }
}
