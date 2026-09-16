package com.holin.android.hardening.artifact

import java.security.MessageDigest

data class BundleEntryAddition(
    val path: String,
    val bytes: ByteArray,
)

object BundleStructuralMetadata {
    fun generate(
        contentSalt: ByteArray,
        applicationId: String,
        sourceAabSha256: String,
        entryCount: Int,
    ): List<BundleEntryAddition> {
        require(contentSalt.isNotEmpty()) { "content salt must not be empty" }
        require(applicationId.isNotBlank()) { "applicationId must not be blank" }
        require(SHA_256.matches(sourceAabSha256)) { "source AAB hash must be a lowercase SHA-256" }
        require(entryCount in 0..64) { "structural metadata entry count must be in 0..64" }
        val context = applicationId.toByteArray(Charsets.UTF_8) +
            sourceAabSha256.toByteArray(Charsets.US_ASCII)
        return (0 until entryCount).map { index ->
            val ordinal = byteArrayOf(
                (index ushr 24).toByte(),
                (index ushr 16).toByte(),
                (index ushr 8).toByte(),
                index.toByte(),
            )
            val content = digest(CONTENT_DOMAIN + contentSalt + context + ordinal)
            val name = digest(NAME_DOMAIN + contentSalt + context + ordinal)
                .joinToString("") { byte -> "%02x".format(byte) }
            BundleEntryAddition("$STRUCTURE_PREFIX$name.bin", content)
        }
    }

    private fun digest(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

    const val STRUCTURE_PREFIX = "BUNDLE-METADATA/com.holin.android.hardening/structure/v1/"
    private val CONTENT_DOMAIN = "hardening-structure-content-v1\u0000".toByteArray(Charsets.US_ASCII)
    private val NAME_DOMAIN = "hardening-structure-name-v1\u0000".toByteArray(Charsets.US_ASCII)
    private val SHA_256 = Regex("[0-9a-f]{64}")
}
