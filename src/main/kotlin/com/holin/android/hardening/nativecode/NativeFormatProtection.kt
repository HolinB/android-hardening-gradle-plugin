package com.holin.android.hardening.nativecode

import com.holin.android.hardening.artifact.BundleEntryReplacement
import com.holin.android.hardening.artifact.BundleSemanticVerifier
import com.holin.android.hardening.similarity.CategoryArtifactReport
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.FileSystems
import java.nio.file.Path
import java.security.MessageDigest

data class NativePolicy(
    val enabled: Boolean = false,
    val includes: Set<String> = emptySet(),
    val excludes: Set<String> = emptySet(),
    val minimumCoverage: Double = 0.0,
) {
    init {
        require(minimumCoverage.isFinite() && minimumCoverage in 0.0..1.0)
        require(!enabled || includes.isNotEmpty()) { "Native format conversion requires explicit file scopes" }
        (includes + excludes).forEach {
            require(it.isNotBlank() && !it.startsWith('/') && ".." !in it && '\\' !in it)
            FileSystems.getDefault().getPathMatcher("glob:$it")
        }
    }
    fun accepts(path: String): Boolean = enabled && includes.any { match(it, path) } && excludes.none { match(it, path) }
    fun encode(): String = JsonOutput.toJson(mapOf("schemaVersion" to 1, "enabled" to enabled, "includes" to includes.sorted(),
        "excludes" to excludes.sorted(), "minimumCoverage" to minimumCoverage))
    private fun match(glob: String, path: String) = FileSystems.getDefault().getPathMatcher("glob:$glob").matches(Path.of(path))
    companion object {
        fun decode(text: String): NativePolicy {
            StrictJson.validateDocument(text)
            val p = JsonSlurper().parseText(text) as Map<*, *>
            require(p["schemaVersion"] == 1)
            return NativePolicy(p["enabled"] as Boolean, (p["includes"] as List<*>).map { it as String }.toSet(),
                (p["excludes"] as List<*>).map { it as String }.toSet(), (p["minimumCoverage"] as Number).toDouble())
        }
    }
}

data class NativeFormatPlan(val replacements: List<BundleEntryReplacement>, val report: Map<String, Any>)

object NativeFormatProtection {
    private val marker = "HARDENING-ELF-NONLOAD-v1\u0000".toByteArray(Charsets.US_ASCII)
    fun plan(entries: Map<String, ByteArray>, policy: NativePolicy, salt: ByteArray): NativeFormatPlan {
        val replacements = mutableListOf<BundleEntryReplacement>()
        var selected = 0
        val rows = entries.filterKeys { Regex("[^/]+/lib/[^/]+/[^/]+\\.so").matches(it) }.toSortedMap().map { (path, bytes) ->
            val requested = policy.accepts(path)
            if (requested) selected++
            val attempt = if (requested) runCatching { transform(path, bytes, salt) } else null
            val transformed = attempt?.getOrNull()
            if (transformed != null) replacements += BundleEntryReplacement(path, path, transformed, BundleSemanticVerifier.NATIVE_LOAD_EQUIVALENCE)
            mapOf("path" to path, "selected" to requested, "transformed" to (transformed != null),
                "reason" to if (!requested) "OUTSIDE_EXPLICIT_NATIVE_SCOPE" else if (transformed == null) "UNSUPPORTED_ELF_FORMAT" else "EXACT_ORIGINAL_ELF_WITH_NONLOADED_TRAILER",
                "detail" to attempt?.exceptionOrNull()?.message, "inputSha256" to Sha256.hex(bytes), "outputSha256" to Sha256.hex(transformed ?: bytes),
                "loadFingerprint" to runCatching { CategoryArtifactReport.elfLoadFingerprint(bytes) }.getOrNull(),
                "addedBytes" to ((transformed?.size ?: bytes.size) - bytes.size),
                "loadedCodeSymbolsRelocations" to "UNCHANGED", "effectiveFingerprintChanges" to if (transformed == null) emptyList() else listOf("FILE_SHA256"))
        }
        val coverage = if (selected == 0) 0.0 else replacements.size.toDouble() / selected
        require(!policy.enabled || coverage >= policy.minimumCoverage) { "Native format coverage $coverage is below ${policy.minimumCoverage}" }
        return NativeFormatPlan(replacements, mapOf("schemaVersion" to 1, "enabled" to policy.enabled, "selected" to selected,
            "transformed" to replacements.size, "coverage" to coverage, "entries" to rows,
            "scope" to "Android ELF loader semantics; machine code, SONAME, build-id and all original ELF bytes stay exact"))
    }

    fun transform(path: String, before: ByteArray, salt: ByteArray): ByteArray {
        validate(path, before)
        val result = before + trailer(path, before, salt)
        verify(path, path, before, result, salt)
        return result
    }

    fun verify(oldPath: String, newPath: String, before: ByteArray, after: ByteArray, salt: ByteArray) {
        require(oldPath == newPath)
        validate(oldPath, before)
        validate(newPath, after)
        require(after.size > before.size && after.copyOfRange(0, before.size).contentEquals(before)) { "Native original ELF bytes changed" }
        require(after.copyOfRange(before.size, after.size).contentEquals(trailer(oldPath, before, salt))) { "unexpected Native trailer" }
        require(CategoryArtifactReport.elfLoadFingerprint(before) == CategoryArtifactReport.elfLoadFingerprint(after)) { "Native loaded content changed" }
    }

    private fun trailer(path: String, bytes: ByteArray, salt: ByteArray): ByteArray = marker +
        ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(bytes.size.toLong()).array() +
        MessageDigest.getInstance("SHA-256").digest(salt + path.toByteArray() + MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun validate(path: String, bytes: ByteArray) {
        CategoryArtifactReport.elfLoadFingerprint(bytes)
        val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val wide = bytes[4].toInt() == 2
        val headerSize = if (wide) 64 else 52
        require(bytes.size >= headerSize && bytes[6].toInt() == 1 && b.getInt(20) == 1)
        require(b.getShort(16).toInt() == 3) { "only ET_DYN shared libraries are supported" }
        require(b.getShort(if (wide) 52 else 40).toInt() == headerSize)
        val expected = when (path.split('/').getOrNull(2)) {
            "arm64-v8a" -> 183 to true
            "armeabi-v7a" -> 40 to false
            "x86" -> 3 to false
            "x86_64" -> 62 to true
            else -> error("unsupported Android ABI")
        }
        require(b.getShort(18).toInt() == expected.first && wide == expected.second) { "ELF machine differs from its ABI path" }
        val sectionOffset = if (wide) b.getLong(40) else b.getInt(32).toLong() and 0xffffffffL
        val sectionCount = b.getShort(if (wide) 60 else 48).toInt() and 65535
        val sectionSize = b.getShort(if (wide) 58 else 46).toInt() and 65535
        require(sectionOffset >= 0 && sectionOffset <= bytes.size)
        if (sectionCount > 0) require(sectionSize == if (wide) 64 else 40)
        require(sectionCount.toLong() * sectionSize <= bytes.size - sectionOffset) { "ELF section table is out of range" }
        require(sectionCount != 0 || sectionOffset == 0L) { "extended ELF section numbering is unsupported" }
    }
}
