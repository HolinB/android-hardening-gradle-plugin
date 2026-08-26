package com.holin.android.hardening.artifact

import com.holin.android.hardening.state.Sha256
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class BundleRewriteManifestVerifierTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `verifier requires a successful typed semantic result for each transformed entry`() {
        val ordinary = temporary.resolve("ordinary.aab")
        val candidate = temporary.resolve("candidate.aab")
        zip(ordinary, linkedMapOf("base/dex/classes.dex" to "before".toByteArray()))
        zip(candidate, linkedMapOf("base/dex/classes.dex" to "after".toByteArray()))
        val manifest = BundleRewriteManifest(
            originalAabSha256 = Sha256.file(ordinary),
            contentSaltSha256 = "a".repeat(64),
            entries = listOf(
                BundleRewriteEntry.transformed(
                    oldPath = "base/dex/classes.dex",
                    oldSha256 = Sha256.hex("before".toByteArray()),
                    newPath = "base/dex/classes.dex",
                    newSha256 = Sha256.hex("after".toByteArray()),
                    semanticVerifier = BundleSemanticVerifier.DEX_SEMANTICS,
                ),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            BundleRewriteVerifier().verify(ordinary, candidate, manifest, emptyList())
        }

        val result = BundleRewriteVerifier().verify(
            ordinary,
            candidate,
            manifest,
            listOf(
                BundleSemanticVerificationResult(
                    oldPath = "base/dex/classes.dex",
                    newPath = "base/dex/classes.dex",
                    verifier = BundleSemanticVerifier.DEX_SEMANTICS,
                    successful = true,
                ),
            ),
        )

        assertEquals(1, result.transformedEntryCount)
    }

    @Test
    fun `semantic result codec round trips and rejects unsuccessful persisted results`() {
        val results = listOf(
            BundleSemanticVerificationResult(
                "base/dex/classes.dex",
                "base/dex/classes.dex",
                BundleSemanticVerifier.DEX_SEMANTICS,
                true,
            ),
        )

        assertEquals(results, BundleSemanticVerificationResultCodec.decode(BundleSemanticVerificationResultCodec.encode(results)))
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                BundleSemanticVerificationResultCodec.decode(
                    BundleSemanticVerificationResultCodec.encode(results).replace("true", "false"),
                )
            }.message.orEmpty().contains("unsuccessful"),
        )
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
}
