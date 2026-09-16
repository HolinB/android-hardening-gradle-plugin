package com.holin.android.hardening.artifact

import com.holin.android.hardening.state.Sha256
import groovy.json.JsonSlurper
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

enum class BundleRewriteAction {
    PRESERVED,
    RENAMED,
    TRANSFORMED,
    REMOVED,
    ADDED,
}

/** The verifier family that establishes a transformed entry's semantic equivalence. */
enum class BundleSemanticVerifier {
    DEX_SEMANTICS,
    RESOURCE_SEMANTICS,
}

data class BundleRewriteEntry(
    val action: BundleRewriteAction,
    val oldPath: String?,
    val oldSha256: String?,
    val newPath: String?,
    val newSha256: String?,
    val semanticVerifier: BundleSemanticVerifier? = null,
) {
    init {
        requireActionShape()
    }

    companion object {
        fun preserved(path: String, sha256: String): BundleRewriteEntry =
            BundleRewriteEntry(BundleRewriteAction.PRESERVED, path, sha256, path, sha256)

        fun renamed(oldPath: String, newPath: String, sha256: String): BundleRewriteEntry =
            BundleRewriteEntry(BundleRewriteAction.RENAMED, oldPath, sha256, newPath, sha256)

        fun transformed(
            oldPath: String,
            oldSha256: String,
            newPath: String,
            newSha256: String,
            semanticVerifier: BundleSemanticVerifier,
        ): BundleRewriteEntry = BundleRewriteEntry(
            BundleRewriteAction.TRANSFORMED,
            oldPath,
            oldSha256,
            newPath,
            newSha256,
            semanticVerifier,
        )

        fun removed(path: String, sha256: String): BundleRewriteEntry =
            BundleRewriteEntry(BundleRewriteAction.REMOVED, path, sha256, null, null)

        fun added(path: String, sha256: String): BundleRewriteEntry =
            BundleRewriteEntry(BundleRewriteAction.ADDED, null, null, path, sha256)
    }

    private fun requireActionShape() {
        listOfNotNull(oldPath, newPath).forEach(::requireSafePath)
        listOfNotNull(oldSha256, newSha256).forEach(::requireSha256)
        when (action) {
            BundleRewriteAction.PRESERVED -> require(
                oldPath != null && oldSha256 != null && newPath == oldPath && newSha256 == oldSha256 && semanticVerifier == null,
            ) { "preserved rewrite entries must retain one path and hash" }
            BundleRewriteAction.RENAMED -> require(
                oldPath != null && oldSha256 != null && newPath != null && newPath != oldPath &&
                    newSha256 == oldSha256 && semanticVerifier == null,
            ) { "renamed rewrite entries must retain their hash at a different path" }
            BundleRewriteAction.TRANSFORMED -> require(
                oldPath != null && oldSha256 != null && newPath != null && newSha256 != null && semanticVerifier != null,
            ) { "transformed rewrite entries require both hashes and a typed semantic verifier" }
            BundleRewriteAction.REMOVED -> require(
                oldPath != null && oldSha256 != null && newPath == null && newSha256 == null && semanticVerifier == null,
            ) { "removed rewrite entries must have only the original path and hash" }
            BundleRewriteAction.ADDED -> require(
                oldPath == null && oldSha256 == null && newPath != null && newSha256 != null && semanticVerifier == null,
            ) { "added rewrite entries must have only the new path and hash" }
        }
        require(action == BundleRewriteAction.REMOVED || action == BundleRewriteAction.ADDED ||
            listOfNotNull(oldPath, newPath).none(BundleZipRewriter::isHardeningMetadata)
        ) { "only a removed entry may reference prior hardening metadata" }
        if (action == BundleRewriteAction.ADDED) {
            require(requireNotNull(newPath).startsWith(BundleStructuralMetadata.STRUCTURE_PREFIX)) {
                "added rewrite entries must use the hardening structure metadata prefix"
            }
        }
    }

    private fun requireSafePath(path: String) {
        BundleZipRewriter.requireSafeUniqueEntryNames(listOf(path))
        require(!BundleZipRewriter.isPreviousSignature(path)) { "rewrite manifest must not account for signature entries" }
    }

    private fun requireSha256(value: String) {
        require(SHA_256.matches(value)) { "rewrite manifest contains an invalid SHA-256" }
    }
}

data class BundleRewriteManifest(
    val originalAabSha256: String,
    val contentSaltSha256: String,
    val entries: List<BundleRewriteEntry>,
) {
    init {
        require(SHA_256.matches(originalAabSha256)) { "rewrite manifest original AAB hash is invalid" }
        require(SHA_256.matches(contentSaltSha256)) { "rewrite manifest content salt hash is invalid" }
        val oldPaths = entries.mapNotNull(BundleRewriteEntry::oldPath)
        val newPaths = entries.mapNotNull(BundleRewriteEntry::newPath)
        require(oldPaths.size == oldPaths.toSet().size) { "rewrite manifest has duplicate original paths" }
        require(newPaths.size == newPaths.toSet().size) { "rewrite manifest has duplicate rewritten paths" }
    }
}

data class BundleSemanticVerificationResult(
    val oldPath: String,
    val newPath: String,
    val verifier: BundleSemanticVerifier,
    val successful: Boolean,
)

data class BundleRewriteVerificationResult(
    val preservedEntryCount: Int,
    val renamedEntryCount: Int,
    val transformedEntryCount: Int,
    val removedEntryCount: Int,
    val addedEntryCount: Int,
)

/** Verifies every non-signature AAB entry against its detached rewrite record. */
class BundleRewriteVerifier {
    fun verify(
        ordinaryBundle: Path,
        candidateBundle: Path,
        manifest: BundleRewriteManifest,
        semanticResults: List<BundleSemanticVerificationResult>,
    ): BundleRewriteVerificationResult {
        require(Sha256.file(ordinaryBundle) == manifest.originalAabSha256) {
            "rewrite manifest does not identify the ordinary release AAB"
        }
        val ordinary = entryHashes(ordinaryBundle)
        val candidate = entryHashes(candidateBundle)
        val ordinaryEntries = ordinary.filterKeys { !BundleZipRewriter.isPreviousSignature(it) }
        val candidateEntries = candidate.filterKeys { !BundleZipRewriter.isPreviousSignature(it) }
        val oldPaths = manifest.entries.mapNotNull(BundleRewriteEntry::oldPath).toSet()
        val newPaths = manifest.entries.mapNotNull(BundleRewriteEntry::newPath).toSet()
        require(ordinaryEntries.keys == oldPaths) { "rewrite manifest has unaccounted or missing ordinary entries" }
        require(candidateEntries.keys == newPaths) { "rewrite manifest has undeclared candidate entries" }

        manifest.entries.forEach { entry ->
            val oldHash = entry.oldPath?.let(ordinaryEntries::get)
            require(oldHash == entry.oldSha256) { "rewrite manifest original entry hash does not match" }
            when (entry.action) {
                BundleRewriteAction.PRESERVED,
                BundleRewriteAction.RENAMED,
                -> {
                    val newHash = candidateEntries[requireNotNull(entry.newPath)]
                    require(newHash == entry.newSha256) { "hardened AAB changed a preserved bundle entry" }
                }
                BundleRewriteAction.TRANSFORMED -> {
                    val newHash = candidateEntries[requireNotNull(entry.newPath)]
                    require(newHash == entry.newSha256) { "rewrite manifest transformed entry hash does not match" }
                }
                BundleRewriteAction.REMOVED -> Unit
                BundleRewriteAction.ADDED -> {
                    val newHash = candidateEntries[requireNotNull(entry.newPath)]
                    require(newHash == entry.newSha256) { "rewrite manifest added entry hash does not match" }
                }
            }
        }

        val expectedSemanticResults = manifest.entries
            .filter { it.action == BundleRewriteAction.TRANSFORMED }
            .map {
                SemanticResultKey(
                    oldPath = requireNotNull(it.oldPath),
                    newPath = requireNotNull(it.newPath),
                    verifier = requireNotNull(it.semanticVerifier),
                )
            }
            .toSet()
        val actualSemanticResults = semanticResults.map {
            SemanticResultKey(it.oldPath, it.newPath, it.verifier)
        }
        require(actualSemanticResults.size == actualSemanticResults.toSet().size) {
            "semantic verification has duplicate results"
        }
        require(actualSemanticResults.toSet() == expectedSemanticResults) {
            "semantic verification results do not match transformed entries"
        }
        require(semanticResults.all(BundleSemanticVerificationResult::successful)) {
            "a transformed rewrite entry lacks successful semantic verification"
        }
        return BundleRewriteVerificationResult(
            manifest.entries.count { it.action == BundleRewriteAction.PRESERVED },
            manifest.entries.count { it.action == BundleRewriteAction.RENAMED },
            manifest.entries.count { it.action == BundleRewriteAction.TRANSFORMED },
            manifest.entries.count { it.action == BundleRewriteAction.REMOVED },
            manifest.entries.count { it.action == BundleRewriteAction.ADDED },
        )
    }

    private fun entryHashes(bundle: Path): Map<String, String> = ZipFile(bundle.toFile()).use { archive ->
        val entries = archive.entries().asSequence().toList()
        BundleZipRewriter.requireSafeUniqueEntryNames(entries.map(ZipEntry::getName))
        entries.associate { entry ->
            entry.name to archive.getInputStream(entry).use { input ->
                val digest = MessageDigest.getInstance("SHA-256")
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count > 0) digest.update(buffer, 0, count)
                }
                digest.digest().toHex()
            }
        }
    }

    private data class SemanticResultKey(
        val oldPath: String,
        val newPath: String,
        val verifier: BundleSemanticVerifier,
    )
}

/** Canonical external persistence for a rewrite manifest; it is never stored in an AAB. */
object BundleRewriteManifestCodec {
    fun encode(manifest: BundleRewriteManifest): String = buildString {
        append("{\"schemaVersion\":2,\"originalAabSha256\":").append(json(manifest.originalAabSha256))
        append(",\"contentSaltSha256\":").append(json(manifest.contentSaltSha256)).append(",\"entries\":[")
        manifest.entries.forEachIndexed { index, entry ->
            if (index > 0) append(',')
            append("{\"action\":").append(json(entry.action.name))
            append(",\"oldPath\":").append(jsonOrNull(entry.oldPath))
            append(",\"oldSha256\":").append(jsonOrNull(entry.oldSha256))
            append(",\"newPath\":").append(jsonOrNull(entry.newPath))
            append(",\"newSha256\":").append(jsonOrNull(entry.newSha256))
            append(",\"semanticVerifier\":").append(entry.semanticVerifier?.let { json(it.name) } ?: "null").append('}')
        }
        append("]}\n")
    }

    fun decode(text: String): BundleRewriteManifest {
        val root = JsonSlurper().parseText(text) as? Map<*, *> ?: invalid("rewrite manifest must be an object")
        require(root.keys == setOf("schemaVersion", "originalAabSha256", "contentSaltSha256", "entries")) {
            "rewrite manifest has an invalid schema"
        }
        require(root["schemaVersion"] == 1 || root["schemaVersion"] == 2) { "unsupported rewrite manifest schema" }
        val entries = root["entries"] as? List<*> ?: invalid("rewrite manifest entries must be an array")
        return BundleRewriteManifest(
            originalAabSha256 = root.string("originalAabSha256"),
            contentSaltSha256 = root.string("contentSaltSha256"),
            entries = entries.map(::decodeEntry),
        )
    }

    fun write(path: Path, manifest: BundleRewriteManifest) {
        Files.createDirectories(requireNotNull(path.toAbsolutePath().normalize().parent))
        Files.writeString(path, encode(manifest))
    }

    fun read(path: Path): BundleRewriteManifest = decode(Files.readString(path))

    private fun decodeEntry(value: Any?): BundleRewriteEntry {
        val entry = value as? Map<*, *> ?: invalid("rewrite manifest entry must be an object")
        require(entry.keys == setOf("action", "oldPath", "oldSha256", "newPath", "newSha256", "semanticVerifier")) {
            "rewrite manifest entry has an invalid schema"
        }
        return BundleRewriteEntry(
            action = enumValueOf(entry.string("action")),
            oldPath = entry.nullableString("oldPath"),
            oldSha256 = entry.nullableString("oldSha256"),
            newPath = entry.nullableString("newPath"),
            newSha256 = entry.nullableString("newSha256"),
            semanticVerifier = entry.nullableString("semanticVerifier")?.let { enumValueOf<BundleSemanticVerifier>(it) },
        )
    }

    private fun json(value: String): String = buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
            }
        }
        append('"')
    }

    private fun jsonOrNull(value: String?): String = value?.let(::json) ?: "null"
    private fun Map<*, *>.string(key: String): String = this[key] as? String ?: invalid("$key must be a string")
    private fun Map<*, *>.nullableString(key: String): String? = when (val value = this[key]) {
        null -> null
        is String -> value
        else -> invalid("$key must be a string or null")
    }
    private fun invalid(message: String): Nothing = throw IllegalArgumentException(message)
}

object BundleSemanticVerificationResultCodec {
    fun encode(results: List<BundleSemanticVerificationResult>): String = buildString {
        append("{\"schemaVersion\":1,\"results\":[")
        results.forEachIndexed { index, result ->
            if (index > 0) append(',')
            append("{\"oldPath\":").append(jsonValue(result.oldPath))
            append(",\"newPath\":").append(jsonValue(result.newPath))
            append(",\"verifier\":").append(jsonValue(result.verifier.name))
            append(",\"successful\":").append(result.successful).append('}')
        }
        append("]}\n")
    }

    fun decode(text: String): List<BundleSemanticVerificationResult> {
        val root = JsonSlurper().parseText(text) as? Map<*, *>
            ?: throw IllegalArgumentException("semantic results must be an object")
        require(root.keys == setOf("schemaVersion", "results")) { "semantic results have an invalid schema" }
        require(root["schemaVersion"] == 1) { "unsupported semantic results schema" }
        val values = root["results"] as? List<*>
            ?: throw IllegalArgumentException("semantic results must contain an array")
        return values.map { value ->
            val item = value as? Map<*, *> ?: throw IllegalArgumentException("semantic result must be an object")
            require(item.keys == setOf("oldPath", "newPath", "verifier", "successful")) {
                "semantic result has an invalid schema"
            }
            val result = BundleSemanticVerificationResult(
                oldPath = item["oldPath"] as? String ?: throw IllegalArgumentException("semantic oldPath must be a string"),
                newPath = item["newPath"] as? String ?: throw IllegalArgumentException("semantic newPath must be a string"),
                verifier = (item["verifier"] as? String)?.let { enumValueOf<BundleSemanticVerifier>(it) }
                    ?: throw IllegalArgumentException("semantic verifier must be a string"),
                successful = item["successful"] as? Boolean
                    ?: throw IllegalArgumentException("semantic successful must be a boolean"),
            )
            require(result.successful) { "persisted semantic result is unsuccessful" }
            BundleZipRewriter.requireSafeUniqueEntryNames(listOf(result.oldPath))
            BundleZipRewriter.requireSafeUniqueEntryNames(listOf(result.newPath))
            result
        }.also { results ->
            require(results.distinctBy { Triple(it.oldPath, it.newPath, it.verifier) }.size == results.size) {
                "semantic results contain duplicates"
            }
        }
    }

    fun write(path: Path, results: List<BundleSemanticVerificationResult>) {
        Files.createDirectories(requireNotNull(path.toAbsolutePath().normalize().parent))
        Files.writeString(path, encode(results))
    }

    fun read(path: Path): List<BundleSemanticVerificationResult> = decode(Files.readString(path))

    private fun jsonValue(value: String): String = buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
            }
        }
        append('"')
    }
}

private val SHA_256 = Regex("[0-9a-f]{64}")
private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte) }
