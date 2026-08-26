package com.holin.android.hardening.artifact

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class ApkPayloadRewriterTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `rewrite diversifies every target and preserves every other payload byte`() {
        val original = temporary.resolve("bundletool.apk")
        val rewritten = temporary.resolve("rewritten-unsigned.apk")
        val targets = listOf("res/drawable/vector.xml", "res/layout/screen.xml")
        zip(
            original,
            linkedMapOf(
                "META-INF/MANIFEST.MF" to Entry("old-manifest".encodeToByteArray()),
                "META-INF/CERT.SF" to Entry("old-sf".encodeToByteArray()),
                "META-INF/CERT.RSA" to Entry("old-rsa".encodeToByteArray()),
                "AndroidManifest.xml" to Entry("manifest".encodeToByteArray(), ZipEntry.STORED),
                "resources.arsc" to Entry("resource-table".encodeToByteArray()),
                "res/drawable/vector.xml" to Entry(binaryXml(5, 6), ZipEntry.STORED),
                "res/layout/screen.xml" to Entry(binaryXml(7, 8)),
                "res/layout/unowned.xml" to Entry(binaryXml(9, 10)),
                "res/drawable/hero.png" to Entry("png".encodeToByteArray()),
            ),
        )

        val result = ApkPayloadRewriter().rewrite(original, rewritten, "a".repeat(64), targets)

        assertEquals(targets, result.changedTargetPaths)
        val originalEntries = entries(original)
        val rewrittenEntries = entries(rewritten)
        assertFalse(rewrittenEntries.keys.any(BundleZipRewriter::isPreviousSignature))
        targets.forEach { path ->
            assertFalse(originalEntries.getValue(path).bytes.contentEquals(rewrittenEntries.getValue(path).bytes))
            assertEquals(originalEntries.getValue(path).bytes.size, rewrittenEntries.getValue(path).bytes.size)
            assertEquals(originalEntries.getValue(path).method, rewrittenEntries.getValue(path).method)
        }
        (originalEntries.keys - targets.toSet()).filterNot(BundleZipRewriter::isPreviousSignature).forEach { path ->
            assertContentEquals(originalEntries.getValue(path).bytes, rewrittenEntries.getValue(path).bytes)
            assertEquals(originalEntries.getValue(path).method, rewrittenEntries.getValue(path).method)
        }
        assertEquals(
            targets.toSet(),
            ApkPayloadDiversificationVerifier().verify(original, rewritten, targets).changedTargetPaths,
        )
    }

    @Test
    fun `rewrite with no selected XML preserves payload and strips prior signatures`() {
        val original = temporary.resolve("bundletool-no-targets.apk")
        val rewritten = temporary.resolve("rewritten-no-targets.apk")
        zip(
            original,
            linkedMapOf(
                "META-INF/MANIFEST.MF" to Entry("old-manifest".encodeToByteArray()),
                "META-INF/CERT.RSA" to Entry("old-rsa".encodeToByteArray()),
                "AndroidManifest.xml" to Entry("manifest".encodeToByteArray()),
                "res/layout/unowned.xml" to Entry(binaryXml(9, 10)),
            ),
        )

        val result = ApkPayloadRewriter().rewrite(original, rewritten, "a".repeat(64), emptyList())

        assertEquals(emptyList(), result.changedTargetPaths)
        assertEquals(
            emptySet(),
            ApkPayloadDiversificationVerifier().verify(original, rewritten, emptyList()).changedTargetPaths,
        )
        assertFalse(entries(rewritten).keys.any(BundleZipRewriter::isPreviousSignature))
    }

    @Test
    fun `rewrite normalizes APK entry order timestamps and metadata to identical bytes`() {
        val entries = listOf(
            "resources.arsc" to Entry("resources".toByteArray(), ZipEntry.STORED),
            "res/layout/screen.xml" to Entry(binaryXml(3, 4)),
            "AndroidManifest.xml" to Entry("manifest".toByteArray(), ZipEntry.STORED),
        )
        val firstInput = temporary.resolve("first.apk")
        val secondInput = temporary.resolve("second.apk")
        zipWithMetadata(firstInput, entries, 1_700_000_000_000L, "first archive")
        zipWithMetadata(secondInput, entries.reversed(), 1_800_000_000_000L, "second archive")
        val firstOutput = temporary.resolve("first-unsigned.apk")
        val secondOutput = temporary.resolve("second-unsigned.apk")

        ApkPayloadRewriter().rewrite(firstInput, firstOutput, "a".repeat(64), emptyList())
        ApkPayloadRewriter().rewrite(secondInput, secondOutput, "a".repeat(64), emptyList())

        assertContentEquals(Files.readAllBytes(firstOutput), Files.readAllBytes(secondOutput))
        ZipFile(firstOutput.toFile()).use { archive ->
            val rewritten = archive.entries().asSequence().toList()
            assertEquals(entries.map { entry -> entry.first }.sorted(), rewritten.map(ZipEntry::getName))
            rewritten.forEach { entry ->
                assertEquals(315_532_800_000L, entry.time)
                assertEquals(null, entry.comment)
                assertEquals(null, entry.extra)
            }
            assertEquals(null, archive.comment)
        }
    }

    @Test
    fun `rewrite rejects missing targets and unsafe portable duplicate entries without output`() {
        val original = temporary.resolve("invalid.apk")
        val output = temporary.resolve("must-not-exist.apk")
        zip(
            original,
            linkedMapOf(
                "res/layout/Screen.xml" to Entry(binaryXml(1)),
                "res/layout/screen.xml" to Entry(binaryXml(2)),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            ApkPayloadRewriter().rewrite(original, output, "a".repeat(64), listOf("res/layout/missing.xml"))
        }
        assertFalse(Files.exists(output))
    }

    @Test
    fun `rewrite identifies the selected APK entry when binary XML parsing fails`() {
        val original = temporary.resolve("malformed-binary-xml.apk")
        val output = temporary.resolve("must-not-exist.apk")
        val target = "res/anim/owned_animation.xml"
        zip(
            original,
            linkedMapOf(target to Entry("not-binary-xml".encodeToByteArray())),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ApkPayloadRewriter().rewrite(original, output, "a".repeat(64), listOf(target))
        }

        assertTrue(failure.message.orEmpty().contains(target))
        assertFalse(Files.exists(output))
    }

    @Test
    fun `independent verifier rejects extra missing unchanged and collateral payload changes`() {
        val original = temporary.resolve("original.apk")
        val rewritten = temporary.resolve("rewritten.apk")
        val target = "res/layout/screen.xml"
        zip(
            original,
            linkedMapOf(
                "AndroidManifest.xml" to Entry("manifest".encodeToByteArray()),
                target to Entry(binaryXml(3, 4)),
            ),
        )
        ApkPayloadRewriter().rewrite(original, rewritten, "a".repeat(64), listOf(target))

        val extra = temporary.resolve("extra.apk")
        rewriteEntries(rewritten, extra) { entries -> entries["assets/extra"] = Entry("extra".encodeToByteArray()) }
        val missing = temporary.resolve("missing.apk")
        rewriteEntries(rewritten, missing) { entries -> entries.remove("AndroidManifest.xml") }
        val unchanged = temporary.resolve("unchanged.apk")
        rewriteEntries(rewritten, unchanged) { entries -> entries[target] = Entry(binaryXml(3, 4)) }
        val collateral = temporary.resolve("collateral.apk")
        rewriteEntries(rewritten, collateral) { entries -> entries["AndroidManifest.xml"] = Entry("changed".encodeToByteArray()) }

        listOf(extra, missing, unchanged, collateral).forEach { candidate ->
            assertFailsWith<IllegalArgumentException> {
                ApkPayloadDiversificationVerifier().verify(original, candidate, listOf(target))
            }
        }
    }

    private fun rewriteEntries(source: Path, target: Path, edit: (LinkedHashMap<String, Entry>) -> Unit) {
        val values = LinkedHashMap(entries(source))
        edit(values)
        zip(target, values)
    }

    private fun entries(path: Path): LinkedHashMap<String, Entry> = ZipFile(path.toFile()).use { archive ->
        archive.entries().asSequence().filterNot(ZipEntry::isDirectory).associateTo(linkedMapOf()) { entry ->
            entry.name to Entry(archive.getInputStream(entry).use { it.readBytes() }, entry.method)
        }
    }

    private fun zip(path: Path, entries: LinkedHashMap<String, Entry>) {
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            entries.forEach { (name, value) ->
                val entry = ZipEntry(name).apply {
                    method = value.method
                    if (method == ZipEntry.STORED) {
                        size = value.bytes.size.toLong()
                        compressedSize = value.bytes.size.toLong()
                        crc = CRC32().apply { update(value.bytes) }.value
                    }
                }
                output.putNextEntry(entry)
                output.write(value.bytes)
                output.closeEntry()
            }
        }
    }

    private fun zipWithMetadata(
        path: Path,
        entries: List<Pair<String, Entry>>,
        timestampMillis: Long,
        archiveComment: String,
    ) {
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            output.setComment(archiveComment)
            entries.forEach { (name, value) ->
                val entry = ZipEntry(name).apply {
                    method = value.method
                    time = timestampMillis
                    comment = "$archiveComment:$name"
                    extra = byteArrayOf(0xca.toByte(), 0xfe.toByte(), 0, 0)
                    if (method == ZipEntry.STORED) {
                        size = value.bytes.size.toLong()
                        compressedSize = value.bytes.size.toLong()
                        crc = CRC32().apply { update(value.bytes) }.value
                    }
                }
                output.putNextEntry(entry)
                output.write(value.bytes)
                output.closeEntry()
            }
        }
    }

    private fun binaryXml(vararg lines: Int): ByteArray {
        val stringPoolSize = 36
        val nodeSizes = lines.indices.map { index -> if (index == 0) 36 else 24 }
        val size = 8 + stringPoolSize + nodeSizes.sum()
        return ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(0x0003)
            putShort(8)
            putInt(size)
            putShort(0x0001)
            putShort(28)
            putInt(stringPoolSize)
            putInt(1)
            putInt(0)
            putInt(0x00000100)
            putInt(32)
            putInt(0)
            putInt(0)
            put(1)
            put(1)
            put('x'.code.toByte())
            put(0)
            lines.forEachIndexed { index, line ->
                putShort((if (index == 0) 0x0102 else 0x0103).toShort())
                putShort(16)
                putInt(nodeSizes[index])
                putInt(line)
                putInt(-1)
                putInt(0)
                putInt(0)
                if (index == 0) {
                    putShort(20)
                    putShort(20)
                    putShort(0)
                    putShort(0)
                    putShort(0)
                    putShort(0)
                }
            }
        }.array()
    }

    private data class Entry(
        val bytes: ByteArray,
        val method: Int = ZipEntry.DEFLATED,
    )
}
