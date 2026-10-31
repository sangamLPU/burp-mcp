package net.portswigger.mcp

import java.util.jar.Manifest

/** Build identity compiled into the extension and exposed through existing MCP status tools. */
internal object BuildInfo {
    const val version: String = "1.3.1"
    const val buildId: String = "20261031.1-burp2024.1.1.1"
    const val serverVersion: String = "1.3.1+20261031.1-burp2024.1.1.1"

    /** Checks packaging metadata without using it as the runtime source of identity. */
    fun matchesManifest(manifest: Manifest?): Boolean {
        val attributes = manifest?.mainAttributes ?: return false
        return attributes.getValue("Implementation-Version") == version &&
            attributes.getValue("Build-Id") == buildId
    }
}
