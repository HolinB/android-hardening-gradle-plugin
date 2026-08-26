package com.holin.android.hardening.artifact

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

class OwnedApkBinaryXmlTargetSelector {
    fun select(manifest: BundleRewriteManifest): List<String> {
        val selectedAabPaths = manifest.entries.mapNotNull { entry ->
            val path = entry.newPath ?: return@mapNotNull null
            if (!AAB_XML_PATH.matches(path)) return@mapNotNull null
            if (RAW_XML_PATH.matches(path)) return@mapNotNull null
            when (entry.action) {
                BundleRewriteAction.RENAMED -> path
                BundleRewriteAction.TRANSFORMED -> path.takeIf {
                    entry.semanticVerifier == BundleSemanticVerifier.RESOURCE_SEMANTICS
                }
                BundleRewriteAction.PRESERVED,
                BundleRewriteAction.REMOVED,
                -> null
            }
        }
        BundleZipRewriter.requireSafeUniqueEntryNames(selectedAabPaths)
        val apkPaths = selectedAabPaths.map { path -> path.removePrefix(BASE_PREFIX) }
        require(apkPaths.all(APK_XML_PATH::matches)) { "rewrite manifest produced an invalid binary XML APK target" }
        BundleZipRewriter.requireSafeUniqueEntryNames(apkPaths)
        return apkPaths.sorted()
    }

    private companion object {
        const val BASE_PREFIX = "base/"
        val AAB_XML_PATH = Regex("base/res/(?:[^/]+/)+[^/]+\\.xml")
        val RAW_XML_PATH = Regex("base/res/raw(?:-[^/]+)?/[^/]+\\.xml")
        val APK_XML_PATH = Regex("res/(?:[^/]+/)+[^/]+\\.xml")
    }
}

object ApkBinaryXmlTargetPathDigest {
    fun sha256(paths: Collection<String>): String {
        val sorted = paths.toList().sorted()
        BundleZipRewriter.requireSafeUniqueEntryNames(sorted)
        require(sorted.all(APK_XML_PATH::matches)) { "binary XML target path digest contains a non-XML APK path" }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.updateFramed(DOMAIN.toByteArray(StandardCharsets.UTF_8))
        digest.updateFramed(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(sorted.size).array())
        sorted.forEach { path -> digest.updateFramed(path.toByteArray(StandardCharsets.UTF_8)) }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private fun MessageDigest.updateFramed(value: ByteArray) {
        update(ByteBuffer.allocate(Int.SIZE_BYTES).putInt(value.size).array())
        update(value)
    }

    private const val DOMAIN = "com.holin.android.hardening/1.2.0/apk-binary-xml-target-paths/v1"
    private val APK_XML_PATH = Regex("res/(?:[^/]+/)+[^/]+\\.xml")
}
