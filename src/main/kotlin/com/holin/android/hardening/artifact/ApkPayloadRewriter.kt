package com.holin.android.hardening.artifact

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.util.UUID
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

data class ApkPayloadRewriteResult(
    val changedTargetPaths: List<String>,
)

data class ApkPayloadDiversificationVerification(
    val changedTargetPaths: Set<String>,
)

fun interface ApkPayloadRewriteOperation {
    fun rewrite(
        originalApk: Path,
        unsignedOutput: Path,
        contentSaltSha256: String,
        targetPaths: Collection<String>,
    ): ApkPayloadRewriteResult
}

fun interface ApkPayloadVerificationOperation {
    fun verify(
        originalApk: Path,
        candidateApk: Path,
        targetPaths: Collection<String>,
    ): ApkPayloadDiversificationVerification
}

class ApkPayloadRewriter(
    private val diversifier: BinaryXmlLineNumberDiversifier = BinaryXmlLineNumberDiversifier(),
    private val verifier: ApkPayloadDiversificationVerifier = ApkPayloadDiversificationVerifier(),
) : ApkPayloadRewriteOperation {
    override fun rewrite(
        originalApk: Path,
        unsignedOutput: Path,
        contentSaltSha256: String,
        targetPaths: Collection<String>,
    ): ApkPayloadRewriteResult {
        val source = originalApk.toAbsolutePath().normalize()
        val target = unsignedOutput.toAbsolutePath().normalize()
        require(source != target) { "APK payload rewrite must not modify the Bundletool APK in place" }
        require(Files.isRegularFile(source)) { "Bundletool universal APK is missing" }
        require(!Files.exists(target)) { "unsigned rewritten APK output already exists" }
        val selected = requireTargetPaths(targetPaths)
        Files.createDirectories(requireNotNull(target.parent))
        val temporary = target.resolveSibling(".${target.fileName}.rewrite-${UUID.randomUUID()}")
        try {
            ZipFile(source.toFile()).use { archive ->
                val entries = archive.entries().asSequence().toList()
                BundleZipRewriter.requireSafeUniqueEntryNames(entries.map(ZipEntry::getName))
                selected.forEach { selectedPath ->
                    require(entries.count { !it.isDirectory && it.name == selectedPath } == 1) {
                        "Bundletool universal APK must contain selected binary XML exactly once: $selectedPath"
                    }
                }
                ZipOutputStream(Files.newOutputStream(temporary, CREATE_NEW, WRITE)).use { output ->
                    entries.sortedBy(ZipEntry::getName).forEach { entry ->
                        if (BundleZipRewriter.isPreviousSignature(entry.name)) return@forEach
                        require(entry.name !in selected || !entry.isDirectory) {
                            "selected binary XML APK target is a directory"
                        }
                        val originalBytes = if (entry.isDirectory) {
                            ByteArray(0)
                        } else {
                            archive.getInputStream(entry).use { it.readBytes() }
                        }
                        val outputBytes = if (entry.name in selected) {
                            try {
                                diversifier.diversify(originalBytes, contentSaltSha256, entry.name)
                            } catch (failure: IllegalArgumentException) {
                                throw IllegalArgumentException(
                                    "selected binary XML APK target is invalid: ${entry.name}: ${failure.message}",
                                    failure,
                                )
                            }
                        } else {
                            originalBytes
                        }
                        output.putNextEntry(copyEntry(entry, outputBytes))
                        if (!entry.isDirectory) output.write(outputBytes)
                        output.closeEntry()
                    }
                }
            }
            verifier.verify(source, temporary, selected)
            FileChannel.open(temporary, READ).use { it.force(true) }
            Files.move(temporary, target, ATOMIC_MOVE)
            return ApkPayloadRewriteResult(selected)
        } catch (failure: IllegalArgumentException) {
            throw failure
        } catch (failure: Exception) {
            throw IllegalArgumentException("APK payload rewrite failed (${failure.javaClass.simpleName})")
        } finally {
            runCatching { Files.deleteIfExists(temporary) }
        }
    }

    private fun copyEntry(source: ZipEntry, bytes: ByteArray): ZipEntry = ZipEntry(source.name).apply {
        require(source.method == ZipEntry.STORED || source.method == ZipEntry.DEFLATED) {
            "APK contains an unsupported ZIP compression method"
        }
        method = source.method
        time = DETERMINISTIC_ZIP_TIMESTAMP_MILLIS
        comment = null
        extra = null
        if (method == ZipEntry.STORED) {
            size = bytes.size.toLong()
            compressedSize = bytes.size.toLong()
            crc = CRC32().apply { update(bytes) }.value
        }
    }
}

class ApkPayloadDiversificationVerifier(
    private val binaryXmlVerifier: BinaryXmlLineNumberDiversificationVerifier =
        BinaryXmlLineNumberDiversificationVerifier(),
) : ApkPayloadVerificationOperation {
    override fun verify(
        originalApk: Path,
        candidateApk: Path,
        targetPaths: Collection<String>,
    ): ApkPayloadDiversificationVerification {
        val targets = requireTargetPaths(targetPaths).toSet()
        val original = payloadEntries(originalApk, "pre-mutation Bundletool APK")
        val candidate = payloadEntries(candidateApk, "final signed APK")
        require(original.keys == candidate.keys) { "APK payload entry-name sets differ after signature exclusion" }
        require(targets.all(original::containsKey)) { "APK payload is missing a selected binary XML target" }

        val changedTargets = linkedSetOf<String>()
        original.keys.sorted().forEach { path ->
            val before = original.getValue(path)
            val after = candidate.getValue(path)
            if (path in targets) {
                require(!before.contentEquals(after)) { "selected binary XML APK target is unchanged: $path" }
                require(before.size == after.size) { "selected binary XML APK target changed length: $path" }
                binaryXmlVerifier.verify(before, after)
                changedTargets += path
            } else {
                require(before.contentEquals(after)) { "APK rewrite changed a non-target payload entry: $path" }
            }
        }
        require(changedTargets == targets) { "verified changed APK targets differ from the manifest-selected set" }
        return ApkPayloadDiversificationVerification(changedTargets)
    }

    private fun payloadEntries(apk: Path, label: String): Map<String, ByteArray> {
        require(Files.isRegularFile(apk)) { "$label is missing" }
        return try {
            ZipFile(apk.toFile()).use { archive ->
                val entries = archive.entries().asSequence().toList()
                BundleZipRewriter.requireSafeUniqueEntryNames(entries.map(ZipEntry::getName))
                entries.asSequence()
                    .filterNot(ZipEntry::isDirectory)
                    .filterNot { entry -> BundleZipRewriter.isPreviousSignature(entry.name) }
                    .associate { entry -> entry.name to archive.getInputStream(entry).use { it.readBytes() } }
            }
        } catch (failure: IllegalArgumentException) {
            throw failure
        } catch (failure: Exception) {
            throw IllegalArgumentException("$label is not a readable APK ZIP (${failure.javaClass.simpleName})")
        }
    }
}

private fun requireTargetPaths(paths: Collection<String>): List<String> {
    val selected = paths.toList()
    BundleZipRewriter.requireSafeUniqueEntryNames(selected)
    require(selected.all(APK_BINARY_XML_PATH::matches)) { "APK binary XML target must be an exact res/**/*.xml path" }
    return selected.sorted()
}

private val APK_BINARY_XML_PATH = Regex("res/(?:[^/]+/)+[^/]+\\.xml")
