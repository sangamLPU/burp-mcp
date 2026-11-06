package net.portswigger.mcp

import java.util.jar.Manifest

/** Build identity compiled into the extension and exposed through existing MCP status tools. */
internal object BuildInfo {
    const val version: String = "1.5.0-dev.3"
    const val buildId: String = "20261106.1-connection-origin-dev"
    const val serverVersion: String = "1.5.0-dev.3+20261106.1-connection-origin-dev"

    /** Checks packaging metadata without using it as the runtime source of identity. */
    fun matchesManifest(manifest: Manifest?): Boolean {
        val attributes = manifest?.mainAttributes ?: return false
        return attributes.getValue("Implementation-Version") == version &&
            attributes.getValue("Build-Id") == buildId
    }
}
