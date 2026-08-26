package com.holin.android.hardening.artifact

import com.holin.android.hardening.state.Sha256
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class BundleZipRewriterTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `rewrite strips signatures and detached metadata and emits a typed manifest`() {
        val input = temporary.resolve("ordinary.aab")
        zip(
            input,
            linkedMapOf(
                "base/manifest/AndroidManifest.xml" to byteArrayOf(0, 1, 2, -1),
                "base/dex/classes.dex" to "dex-payload".toByteArray(),
                "META-INF/MANIFEST.MF" to "old manifest".toByteArray(),
                "META-INF/RELEASE.SF" to "old sf".toByteArray(),
                "META-INF/RELEASE.RSA" to "old rsa".toByteArray(),
                "META-INF/SIG-OLD" to "old sig".toByteArray(),
                "BUNDLE-METADATA/com.holin.android.hardening/old.json" to "old metadata".toByteArray(),
                "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map" to "r8 mapping".toByteArray(),
            ),
        )
        val output = temporary.resolve("unsigned.aab")
        val saltHash = "c".repeat(64)

        val result = BundleZipRewriter().rewrite(input, output, saltHash)

        assertEquals(Sha256.file(input), result.originalAabSha256)
        assertEquals(
            setOf(
                "base/manifest/AndroidManifest.xml",
                "base/dex/classes.dex",
            ),
            entryNames(output),
        )
        assertTrue(entryBytes(output, "base/manifest/AndroidManifest.xml").contentEquals(byteArrayOf(0, 1, 2, -1)))
        assertEquals("dex-payload", entryBytes(output, "base/dex/classes.dex").toString(Charsets.UTF_8))
        assertEquals(
            BundleRewriteManifest(
                Sha256.file(input),
                saltHash,
                listOf(
                    BundleRewriteEntry.removed(
                        "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map",
                        Sha256.hex("r8 mapping".toByteArray()),
                    ),
                    BundleRewriteEntry.removed(
                        "BUNDLE-METADATA/com.holin.android.hardening/old.json",
                        Sha256.hex("old metadata".toByteArray()),
                    ),
                    BundleRewriteEntry.preserved(
                        "base/dex/classes.dex",
                        Sha256.hex("dex-payload".toByteArray()),
                    ),
                    BundleRewriteEntry.preserved(
                        "base/manifest/AndroidManifest.xml",
                        Sha256.hex(byteArrayOf(0, 1, 2, -1)),
                    ),
                ),
            ),
            result.manifest,
        )
        assertEquals(
            setOf("base/manifest/AndroidManifest.xml", "base/dex/classes.dex"),
            result.preservedEntrySha256.keys,
        )
        assertFalse(output.readBytes().toString(Charsets.ISO_8859_1).contains(temporary.toString()))
    }

    @Test
    fun `rewrite normalizes entry order timestamps and metadata to identical bytes`() {
        val entries = listOf(
            "base/res/layout/screen.xml" to "layout".toByteArray(),
            "base/dex/classes.dex" to "dex".toByteArray(),
            "BundleConfig.pb" to "config".toByteArray(),
        )
        val firstInput = temporary.resolve("first.aab")
        val secondInput = temporary.resolve("second.aab")
        zipWithMetadata(firstInput, entries, 1_700_000_000_000L, "first archive")
        zipWithMetadata(secondInput, entries.reversed(), 1_800_000_000_000L, "second archive")
        val firstOutput = temporary.resolve("first-unsigned.aab")
        val secondOutput = temporary.resolve("second-unsigned.aab")

        BundleZipRewriter().rewrite(firstInput, firstOutput, "c".repeat(64))
        BundleZipRewriter().rewrite(secondInput, secondOutput, "c".repeat(64))

        assertTrue(Files.readAllBytes(firstOutput).contentEquals(Files.readAllBytes(secondOutput)))
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
    fun `rewrite rejects unsafe entry names before publishing output`() {
        val input = temporary.resolve("unsafe.aab")
        zip(input, linkedMapOf("../escape.dex" to "escape".toByteArray()))
        val output = temporary.resolve("unsigned.aab")

        assertFailsWith<IllegalArgumentException> {
            BundleZipRewriter().rewrite(input, output, "c".repeat(64))
        }

        assertFalse(Files.exists(output))
    }

    @Test
    fun `verified replacements are renamed or transformed without claiming semantic success`() {
        val input = temporary.resolve("ordinary.aab")
        zip(
            input,
            linkedMapOf(
                "base/res/layout/old.xml" to "same".toByteArray(),
                "base/dex/classes.dex" to "before".toByteArray(),
            ),
        )
        val output = temporary.resolve("unsigned.aab")

        val result = BundleZipRewriter().rewrite(
            input,
            output,
            "d".repeat(64),
            replacements = listOf(
                BundleEntryReplacement(
                    oldPath = "base/res/layout/old.xml",
                    newPath = "base/res/layout/new.xml",
                    bytes = "same".toByteArray(),
                    semanticVerifier = null,
                ),
                BundleEntryReplacement(
                    oldPath = "base/dex/classes.dex",
                    newPath = "base/dex/classes.dex",
                    bytes = "after".toByteArray(),
                    semanticVerifier = BundleSemanticVerifier.DEX_SEMANTICS,
                ),
            ),
        )

        assertEquals(setOf("base/res/layout/new.xml", "base/dex/classes.dex"), entryNames(output))
        assertEquals(1, result.manifest.entries.count { it.action == BundleRewriteAction.RENAMED })
        assertEquals(1, result.manifest.entries.count { it.action == BundleRewriteAction.TRANSFORMED })
    }

    @Test
    fun `replacement path collision fails before publishing output`() {
        val input = temporary.resolve("ordinary.aab")
        zip(input, linkedMapOf("base/a" to byteArrayOf(1), "base/b" to byteArrayOf(2)))

        assertFailsWith<IllegalArgumentException> {
            BundleZipRewriter().rewrite(
                input,
                temporary.resolve("unsigned.aab"),
                "d".repeat(64),
                replacements = listOf(BundleEntryReplacement("base/a", "base/b", byteArrayOf(1), null)),
            )
        }
        assertFalse(Files.exists(temporary.resolve("unsigned.aab")))
    }

    @Test
    fun `entry validation rejects duplicate and platform ambiguous names`() {
        assertFailsWith<IllegalArgumentException> {
            BundleZipRewriter.requireSafeUniqueEntryNames(listOf("base/a.dex", "base/a.dex"))
        }
        assertFailsWith<IllegalArgumentException> {
            BundleZipRewriter.requireSafeUniqueEntryNames(listOf("base/a.dex", "base\\a.dex"))
        }
        assertFailsWith<IllegalArgumentException> {
            BundleZipRewriter.requireSafeUniqueEntryNames(listOf("/absolute.dex"))
        }
    }

    private fun zip(path: Path, entries: LinkedHashMap<String, ByteArray>) {
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            entries.forEach { (name, bytes) ->
                output.putNextEntry(ZipEntry(name))
                output.write(bytes)
                output.closeEntry()
            }
        }
    }

    private fun zipWithMetadata(
        path: Path,
        entries: List<Pair<String, ByteArray>>,
        timestampMillis: Long,
        archiveComment: String,
    ) {
        ZipOutputStream(Files.newOutputStream(path)).use { output ->
            output.setComment(archiveComment)
            entries.forEach { (name, bytes) ->
                val entry = ZipEntry(name)
                entry.time = timestampMillis
                entry.comment = "$archiveComment:$name"
                entry.extra = byteArrayOf(0xca.toByte(), 0xfe.toByte(), 0, 0)
                output.putNextEntry(entry)
                output.write(bytes)
                output.closeEntry()
            }
        }
    }

    private fun entryNames(path: Path): Set<String> = ZipFile(path.toFile()).use { zip ->
        zip.entries().asSequence().map(ZipEntry::getName).toSet()
    }

    private fun entryBytes(path: Path, name: String): ByteArray = ZipFile(path.toFile()).use { zip ->
        zip.getInputStream(requireNotNull(zip.getEntry(name))).readBytes()
    }
}
