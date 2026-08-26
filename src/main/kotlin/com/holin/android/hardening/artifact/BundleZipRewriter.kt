package com.holin.android.hardening.artifact

import com.holin.android.hardening.state.Sha256
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.READ
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

internal const val DETERMINISTIC_ZIP_TIMESTAMP_MILLIS = 315_532_800_000L

data class BundleRewriteResult(
    val originalAabSha256: String,
    val preservedEntrySha256: Map<String, String>,
    val manifest: BundleRewriteManifest,
)

data class BundleEntryReplacement(
    val oldPath: String,
    val newPath: String,
    val bytes: ByteArray,
    val semanticVerifier: BundleSemanticVerifier?,
)

/**
 * Creates the unsigned, independently publishable AAB copy used by the
 * hardening pipeline. It never mutates AGP's canonical bundle artifact.
 */
class BundleZipRewriter {
    fun rewrite(
        input: Path,
        output: Path,
        contentSaltSha256: String,
        replacements: Collection<BundleEntryReplacement> = emptyList(),
    ): BundleRewriteResult {
        require(Files.isRegularFile(input)) { "ordinary AAB input is missing" }
        requireSha256(contentSaltSha256, "contentSaltSha256")
        val source = input.toAbsolutePath().normalize()
        val target = output.toAbsolutePath().normalize()
        require(source != target) { "hardening AAB rewrite must not modify the ordinary bundle in place" }

        val originalHash = Sha256.file(source)
        val preserved = linkedMapOf<String, String>()
        val manifestEntries = mutableListOf<BundleRewriteEntry>()
        val replacementsByOldPath = replacements.associateBy(BundleEntryReplacement::oldPath)
        require(replacementsByOldPath.size == replacements.size) { "bundle replacements contain duplicate source paths" }
        replacements.forEach { replacement ->
            requireSafeUniqueEntryNames(listOf(replacement.oldPath))
            requireSafeUniqueEntryNames(listOf(replacement.newPath))
            require(!isPreviousSignature(replacement.oldPath) && !isPreviousSignature(replacement.newPath)) {
                "bundle replacements cannot target signature entries"
            }
            require(!isHardeningMetadata(replacement.oldPath) && !isHardeningMetadata(replacement.newPath)) {
                "bundle replacements cannot target hardening metadata"
            }
            require(!isEmbeddedR8Mapping(replacement.oldPath) && !isEmbeddedR8Mapping(replacement.newPath)) {
                "bundle replacements cannot target the detached R8 mapping"
            }
        }
        Files.createDirectories(requireNotNull(target.parent))
        val temporary = target.parent.resolve(".${target.fileName}.tmp-${UUID.randomUUID()}")
        try {
            ZipFile(source.toFile()).use { archive ->
                val entries = archive.entries().asSequence().toList()
                requireSafeUniqueEntryNames(entries.map(ZipEntry::getName))
                val inputNames = entries.map(ZipEntry::getName).toSet()
                require(replacementsByOldPath.keys.all(inputNames::contains)) { "bundle replacement source entry is missing" }
                val finalNames = entries.mapNotNull { entry ->
                    when {
                        isPreviousSignature(entry.name) || isDetachedMetadata(entry.name) -> null
                        else -> replacementsByOldPath[entry.name]?.newPath ?: entry.name
                    }
                }
                requireSafeUniqueEntryNames(finalNames)
                val orderedEntries = entries.sortedBy { entry ->
                    replacementsByOldPath[entry.name]?.newPath ?: entry.name
                }
                ZipOutputStream(Files.newOutputStream(temporary)).use { rewritten ->
                    orderedEntries.forEach { entry ->
                        if (isPreviousSignature(entry.name)) return@forEach
                        val digest = archive.entrySha256(entry)
                        if (isDetachedMetadata(entry.name)) {
                            manifestEntries += BundleRewriteEntry.removed(entry.name, digest)
                            return@forEach
                        }
                        val replacement = replacementsByOldPath[entry.name]
                        require(replacement == null || !entry.isDirectory) { "bundle directory entries cannot be replaced" }
                        val newName = replacement?.newPath ?: entry.name
                        val copy = ZipEntry(newName).apply {
                            time = DETERMINISTIC_ZIP_TIMESTAMP_MILLIS
                            comment = null
                            extra = null
                        }
                        rewritten.putNextEntry(copy)
                        if (!entry.isDirectory) {
                            if (replacement == null) {
                                archive.getInputStream(entry).use { inputStream ->
                                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                                    while (true) {
                                        val count = inputStream.read(buffer)
                                        if (count < 0) break
                                        if (count == 0) continue
                                        rewritten.write(buffer, 0, count)
                                    }
                                }
                                preserved[entry.name] = digest
                            } else {
                                rewritten.write(replacement.bytes)
                            }
                        }
                        rewritten.closeEntry()
                        if (replacement == null) {
                            manifestEntries += BundleRewriteEntry.preserved(entry.name, digest)
                        } else {
                            val newDigest = Sha256.hex(replacement.bytes)
                            if (newDigest == digest) {
                                require(replacement.newPath != entry.name) {
                                    "bundle replacement does not change path or bytes"
                                }
                                require(replacement.semanticVerifier == null) {
                                    "a path-only bundle rename must not claim semantic transformation"
                                }
                                manifestEntries += BundleRewriteEntry.renamed(entry.name, replacement.newPath, digest)
                            } else {
                                val verifier = requireNotNull(replacement.semanticVerifier) {
                                    "a changed bundle entry requires a semantic verifier"
                                }
                                manifestEntries += BundleRewriteEntry.transformed(
                                    entry.name,
                                    digest,
                                    replacement.newPath,
                                    newDigest,
                                    verifier,
                                )
                            }
                        }
                    }
                }
            }
            FileChannel.open(temporary, READ).use { it.force(true) }
            Files.move(temporary, target, ATOMIC_MOVE, REPLACE_EXISTING)
            forceDirectory(target.parent)
        } finally {
            Files.deleteIfExists(temporary)
        }
        return BundleRewriteResult(
            originalAabSha256 = originalHash,
            preservedEntrySha256 = preserved,
            manifest = BundleRewriteManifest(originalHash, contentSaltSha256, manifestEntries),
        )
    }

    companion object {
        fun requireSafeUniqueEntryNames(names: Collection<String>) {
            val portableNames = linkedSetOf<String>()
            names.forEach { name ->
                require(name.isNotEmpty() && '\u0000' !in name) { "AAB contains an empty or NUL ZIP entry name" }
                require('\\' !in name) { "AAB ZIP entry names must use forward slashes" }
                require(!name.startsWith('/')) { "AAB contains an absolute ZIP entry name" }
                require(!WINDOWS_ABSOLUTE.containsMatchIn(name)) { "AAB contains a platform-absolute ZIP entry name" }
                val withoutDirectoryMarker = name.removeSuffix("/")
                require(withoutDirectoryMarker.isNotEmpty()) { "AAB contains an invalid root directory entry" }
                val components = withoutDirectoryMarker.split('/')
                require(components.none { it.isEmpty() || it == "." || it == ".." }) {
                    "AAB contains an unsafe ZIP entry name"
                }
                val portable = name.lowercase(Locale.ROOT)
                require(portableNames.add(portable)) { "AAB contains duplicate or platform-ambiguous ZIP entry names" }
            }
        }

        internal fun isPreviousSignature(name: String): Boolean {
            val components = name.split('/')
            if (components.size != 2 || !components[0].equals("META-INF", ignoreCase = true)) return false
            val leaf = components[1].uppercase(Locale.ROOT)
            return leaf == "MANIFEST.MF" ||
                leaf.startsWith("SIG-") ||
                SIGNATURE_SUFFIXES.any(leaf::endsWith)
        }

        internal fun isHardeningMetadata(name: String): Boolean =
            name.startsWith(HARDENING_METADATA_PREFIX, ignoreCase = true)

        internal fun isEmbeddedR8Mapping(name: String): Boolean =
            name.equals(EMBEDDED_R8_MAPPING_PATH, ignoreCase = true)

        private fun isDetachedMetadata(name: String): Boolean =
            isHardeningMetadata(name) || isEmbeddedR8Mapping(name)

        private fun requireSha256(value: String, name: String) {
            require(SHA_256.matches(value)) { "$name must be a lowercase SHA-256 value" }
        }

        private fun forceDirectory(directory: Path) {
            runCatching { FileChannel.open(directory, READ).use { it.force(true) } }
        }

        private const val HARDENING_METADATA_PREFIX =
            "BUNDLE-METADATA/com.holin.android.hardening/"
        private const val EMBEDDED_R8_MAPPING_PATH =
            "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map"
        private val SIGNATURE_SUFFIXES = listOf(".SF", ".RSA", ".DSA", ".EC")
        private val SHA_256 = Regex("[0-9a-f]{64}")
        private val WINDOWS_ABSOLUTE = Regex("^[A-Za-z]:/")
    }
}

private fun ZipFile.entrySha256(entry: ZipEntry): String = getInputStream(entry).use { input ->
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    while (true) {
        val count = input.read(buffer)
        if (count < 0) break
        if (count > 0) digest.update(buffer, 0, count)
    }
    digest.digest().joinToString("") { byte -> "%02x".format(byte) }
}
