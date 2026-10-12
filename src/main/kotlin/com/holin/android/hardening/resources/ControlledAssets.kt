package com.holin.android.hardening.resources

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.artifact.BundleEntryReplacement
import com.holin.android.hardening.artifact.BundleSemanticVerifier
import com.holin.android.hardening.inventory.GitIgnoreMatcher
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

data class AssetPolicy(
    val enabled: Boolean = false,
    val includes: Set<String> = setOf("**"),
    val excludes: Set<String> = emptySet(),
    val images: Boolean = false,
    val fonts: Boolean = false,
    val json: Boolean = false,
    val minimumCoverage: Double = 0.0,
) {
    init {
        require(minimumCoverage.isFinite() && minimumCoverage in 0.0..1.0)
        require(includes.isNotEmpty())
        (includes + excludes).forEach {
            require(it.isNotBlank() && !it.startsWith('/') && ".." !in it && '\\' !in it)
            FileSystems.getDefault().getPathMatcher("glob:$it")
        }
    }
    fun encode(): String = JsonOutput.toJson(mapOf("schemaVersion" to 1, "enabled" to enabled,
        "includes" to includes.sorted(), "excludes" to excludes.sorted(), "images" to images,
        "fonts" to fonts, "json" to json, "minimumCoverage" to minimumCoverage))
    fun accepts(path: String): Boolean = includes.any { matches(it, path) } && excludes.none { matches(it, path) }
    private fun matches(pattern: String, path: String) = FileSystems.getDefault().getPathMatcher("glob:$pattern").matches(Path.of(path))
    companion object {
        fun decode(json: String): AssetPolicy {
            StrictJson.validateDocument(json)
            val v = JsonSlurper().parseText(json) as Map<*, *>
            require(v["schemaVersion"] == 1)
            return AssetPolicy(v["enabled"] as Boolean, (v["includes"] as List<*>).map { it as String }.toSet(),
                (v["excludes"] as List<*>).map { it as String }.toSet(), v["images"] as Boolean,
                v["fonts"] as Boolean, v["json"] as Boolean, (v["minimumCoverage"] as Number).toDouble())
        }
    }
}

data class ControlledAssetPlan(val replacements: List<BundleEntryReplacement>, val report: Map<String, Any>)

object ControlledAssets {
    fun plan(root: Path, ownership: HardeningOwnership, entries: Map<String, ByteArray>, policy: AssetPolicy, salt: ByteArray): ControlledAssetPlan {
        val sourceCandidates = mutableMapOf<String, MutableList<Pair<String, Path>>>()
        if (policy.enabled) ownership.modules.forEach { module -> module.sourceRoots.assetDirectories.forEach { directory ->
            require(directory.startsWith(root) && !Files.isSymbolicLink(directory)) { "asset root must remain within the repository" }
            if (Files.isDirectory(directory, NOFOLLOW_LINKS)) Files.walk(directory).use { paths ->
                paths.forEach { file ->
                    require(!Files.isSymbolicLink(file)) { "symbolic assets are not supported" }
                    if (Files.isRegularFile(file, NOFOLLOW_LINKS)) {
                        val relative = directory.relativize(file).toString().replace('\\', '/')
                        sourceCandidates.getOrPut("base/assets/$relative") { mutableListOf() }.add(module.path to file)
                    }
                }
            }
        } }
        val ignored = GitIgnoreMatcher(root).ignored(sourceCandidates.values.flatten().map { it.second })
        val replacements = mutableListOf<BundleEntryReplacement>()
        var scoped = 0
        val records = entries.filterKeys { "/assets/" in it }.toSortedMap().map { (path, bytes) ->
            val relative = path.substringAfter("/assets/")
            val sources = sourceCandidates[path].orEmpty().filter { it.second !in ignored && Files.readAllBytes(it.second).contentEquals(bytes) }
            val ext = relative.substringAfterLast('.').lowercase()
            val requested = policy.enabled && policy.accepts(relative)
            if (requested) scoped++
            var reason = when {
                !policy.enabled -> "DISABLED"
                !requested -> "OUTSIDE_CONFIGURED_SCOPE"
                sources.isEmpty() -> "DEPENDENCY_GENERATED_OR_UNPROVEN_SOURCE"
                ext in setOf("pem", "cer", "crt", "der", "p12", "bks", "jks") -> "CERTIFICATE_CONTRACT"
                ext in setOf("png", "webp", "jpg", "jpeg") && policy.images -> "PIXEL_EXACT"
                ext in setOf("ttf", "otf") && policy.fonts -> "SFNT_TABLE_EQUIVALENCE"
                ext == "json" && policy.json -> "JSON_TOKEN_EQUIVALENCE"
                else -> "FORMAT_OR_READER_NOT_PROVEN"
            }
            var after: ByteArray? = null
            var detail: String? = null
            if (reason in setOf("PIXEL_EXACT", "SFNT_TABLE_EQUIVALENCE", "JSON_TOKEN_EQUIVALENCE")) {
                val result = runCatching {
                    when (reason) {
                        "PIXEL_EXACT" -> PixelPreservingImageTransformer.transform(bytes, path, salt)
                        "SFNT_TABLE_EQUIVALENCE" -> SfntFontDiversifier().diversify(bytes, salt, path)
                        else -> JsonAssetEquivalence.transform(bytes)
                    }.also { candidate ->
                        require(!bytes.contentEquals(candidate)) { "ineffective format conversion" }
                        verify(path, path, bytes, candidate, salt)
                    }
                }
                after = result.getOrNull()
                if (result.isFailure) {
                    detail = result.exceptionOrNull()?.message?.take(240)
                    reason = "EQUIVALENCE_NOT_PROVEN"
                }
            }
            if (after != null) replacements.add(BundleEntryReplacement(path, path, after, BundleSemanticVerifier.ASSET_FORMAT_EQUIVALENCE))
            mapOf("path" to path, "inputSha256" to Sha256.hex(bytes), "inputBytes" to bytes.size,
                "origin" to if (sources.isEmpty()) "UNPROVEN" else "OWNED_SOURCE_EXACT_BYTES",
                "sources" to sources.map { (module, file) -> mapOf("module" to module, "source" to root.relativize(file).toString()) },
                "status" to if (after == null) "PRESERVED" else "TRANSFORMED", "reason" to reason,
                "detail" to detail, "outputSha256" to Sha256.hex(after ?: bytes),
                "pathStatus" to "PRESERVED_READER_CONTRACT")
        }
        val coverage = if (scoped == 0) 0.0 else replacements.size.toDouble() / scoped
        require(!policy.enabled || coverage + 1e-12 >= policy.minimumCoverage) { "asset proven coverage $coverage is below ${policy.minimumCoverage}" }
        return ControlledAssetPlan(replacements, mapOf("schemaVersion" to 1, "enabled" to policy.enabled,
            "discovered" to records.size, "scoped" to scoped, "transformed" to replacements.size,
            "coverage" to coverage, "entries" to records))
    }

    fun verify(oldPath: String, newPath: String, before: ByteArray, after: ByteArray, salt: ByteArray) {
        require(oldPath.startsWith("base/assets/") && newPath == oldPath) { "asset format verification cannot authorize path changes" }
        when (oldPath.substringAfterLast('.').lowercase()) {
            "png", "webp", "jpg", "jpeg" -> PixelPreservingImageTransformer.verify(before, after, oldPath)
            "ttf", "otf" -> SfntFontDiversifier().verify(before, after, salt, oldPath)
            "json" -> JsonAssetEquivalence.verify(before, after)
            else -> throw IllegalArgumentException("no typed asset format verifier")
        }
    }
}

/** Retains the exact token stream, including number spellings, escape sequences and member order. */
object JsonAssetEquivalence {
    fun transform(before: ByteArray): ByteArray {
        val tokens = tokens(before)
        val compact = tokens.toByteArray(Charsets.UTF_8)
        return if (compact.contentEquals(before)) ("\n" + tokens).toByteArray(Charsets.UTF_8) else compact
    }
    fun verify(before: ByteArray, after: ByteArray) {
        require(!before.contentEquals(after) && tokens(before) == tokens(after)) { "JSON tokens changed" }
    }
    private fun tokens(bytes: ByteArray): String {
        val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
        val text = decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        StrictJson.validateDocument(text)
        var quoted = false; var escaped = false
        return buildString {
            text.forEach { c ->
                if (quoted || c !in " \t\r\n") append(c)
                if (escaped) escaped = false
                else if (quoted && c == '\\') escaped = true
                else if (c == '"') quoted = !quoted
            }
        }
    }
}
