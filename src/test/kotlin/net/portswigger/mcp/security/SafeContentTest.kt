package net.portswigger.mcp.security

import net.portswigger.mcp.tools.SecurityAnalysis
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.Base64

class SafeContentTest {
    @Test
    fun `raw HTTP rendering redacts secrets and marks captured text untrusted`() {
        val jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue123"
        val raw = """GET /?access_token=url-secret HTTP/1.1
            |Host: example.test
            |Authorization: Bearer header-secret
            |Cookie: session=cookie-secret
            |Content-Type: application/json
            |
            |{"api_key":"body-secret","jwt":"$jwt","message":"hello"}""".trimMargin()

        val rendered = SafeContent.redactRaw(raw)

        assertTrue(rendered.contains("UNTRUSTED CAPTURED DATA"))
        listOf("url-secret", "header-secret", "cookie-secret", "body-secret", jwt).forEach {
            assertFalse(rendered.contains(it), "Expected secret to be redacted: $it")
        }
        assertTrue(rendered.contains("[REDACTED]"))
    }

    @Test
    fun `binary bodies are omitted`() {
        val raw = "GET / HTTP/1.1\nHost: example.test\n\n\u0000\u0001\u0002\u0003"
        val rendered = SafeContent.redactRaw(raw)
        assertTrue(rendered.contains("binary body omitted"))
    }

    @Test
    fun `pending metadata path redacts all query values and sensitive names`() {
        val path = SafeContent.redactMetadataPath(
            "/token/path-secret/account?tab=orders&access_token=private-token&email=person@example.test#section"
        )
        assertEquals("/token/[REDACTED]/account?[query redacted]", path)
        listOf("path-secret", "orders", "private-token", "person@example.test", "access_token").forEach {
            assertFalse(path.contains(it))
        }
    }

    @Test
    fun `disclosed preview redacts sensitive headers and encoded sensitive query keys`() {
        val raw = """GET /callback?oauth%5Fcode=authorization-secret&utm_source=campaign HTTP/1.1
            |Host: example.test
            |X-Session-ID: session-secret
            |X-Api-Key: api-secret
            |Cookie: session=cookie-secret
            |Accept: application/json
            |
            |ok""".trimMargin()
        val rendered = SafeContent.redactRaw(raw)
        listOf("authorization-secret", "session-secret", "api-secret", "cookie-secret").forEach {
            assertFalse(rendered.contains(it), "Sensitive value leaked: $it")
        }
        assertTrue(rendered.contains("Accept: application/json"))
        assertTrue(rendered.contains("utm_source=campaign"))
    }

    @Test
    fun `base64 raw request parsing is bounded and validates input`() {
        val encoded = Base64.getEncoder().encodeToString("GET / HTTP/1.1".toByteArray())
        assertEquals("GET / HTTP/1.1", String(SafeContent.decodeRawRequestBase64(encoded)))
        assertThrows(IllegalArgumentException::class.java) {
            SafeContent.decodeRawRequestBase64("not-base64!")
        }
        assertThrows(IllegalArgumentException::class.java) {
            SafeContent.decodeRawRequestBase64("A".repeat(SafeContent.MAX_REQUEST_BYTES * 2 + 4))
        }
    }

    @Test
    fun `heuristic findings are not labeled as confirmed vulnerabilities`() {
        val findings = SecurityAnalysis.securityHeaders(emptyMap(), https = true)
        assertTrue(findings.isNotEmpty())
        assertTrue(findings.all { it.classification == "suspicious" })
        assertTrue(findings.all { it.confidence == "manual_verification_required" })
    }

    @Test
    fun `cookie analysis never returns cookie values`() {
        val findings = SecurityAnalysis.cookies(listOf("session=private-cookie-value; Path=/"), https = true)
        assertTrue(findings.isNotEmpty())
        assertFalse(findings.toString().contains("private-cookie-value"))
    }
}
