package com.holin.android.hardening.artifact

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class VerifiedArtifactPublisherTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `commit failure restores the prior bundle and report`() {
        val sourceBundle = file("source.aab", "new-aab")
        val sourceReport = file("source.json", "new-report")
        val targetBundle = file("published/app.aab", "old-aab")
        val targetReport = file("reports/report.json", "old-report")

        assertFailsWith<IllegalStateException> {
            VerifiedArtifactPublisher().publish(
                sourceBundle,
                sourceReport,
                targetBundle,
                targetReport,
            ) {
                throw IllegalStateException("archive conflict")
            }
        }

        assertEquals("old-aab", targetBundle.readText())
        assertEquals("old-report", targetReport.readText())
        assertFalse(temporary.toFile().walkTopDown().any { it.name.contains(".hardening-tmp-") })
    }

    @Test
    fun `successful commit publishes both files and removes backups`() {
        val sourceBundle = file("source.aab", "new-aab")
        val sourceReport = file("source.json", "new-report")
        val targetBundle = temporary.resolve("published/app.aab")
        val targetReport = temporary.resolve("reports/report.json")
        var committed = false

        VerifiedArtifactPublisher().publish(
            sourceBundle,
            sourceReport,
            targetBundle,
            targetReport,
        ) {
            committed = true
        }

        assertEquals(true, committed)
        assertEquals("new-aab", targetBundle.readText())
        assertEquals("new-report", targetReport.readText())
        assertFalse(temporary.toFile().walkTopDown().any { it.name.contains(".hardening-tmp-") })
    }

    @Test
    fun `commit failure restores bundle and both published reports`() {
        val sourceBundle = file("source.aab", "new-aab")
        val sourceBundleReport = file("source-bundle.json", "new-bundle-report")
        val sourceMappingReport = file("source-mapping.json", "new-mapping-report")
        val targetBundle = file("published/app.aab", "old-aab")
        val targetBundleReport = file("reports/bundle.json", "old-bundle-report")
        val targetMappingReport = file("reports/mapping.json", "old-mapping-report")

        assertFailsWith<IllegalStateException> {
            VerifiedArtifactPublisher().publish(
                publications = listOf(
                    VerifiedArtifactPublisher.Publication(sourceBundle, targetBundle),
                    VerifiedArtifactPublisher.Publication(sourceBundleReport, targetBundleReport),
                    VerifiedArtifactPublisher.Publication(sourceMappingReport, targetMappingReport),
                ),
            ) {
                throw IllegalStateException("archive conflict")
            }
        }

        assertEquals("old-aab", targetBundle.readText())
        assertEquals("old-bundle-report", targetBundleReport.readText())
        assertEquals("old-mapping-report", targetMappingReport.readText())
        assertFalse(temporary.toFile().walkTopDown().any { it.name.contains(".hardening-tmp-") })
    }

    @Test
    fun `cleanup failure after commit never rolls back published artifacts`() {
        val sourceBundle = file("source.aab", "new-aab")
        val sourceReport = file("source.json", "new-report")
        val targetBundle = file("published/app.aab", "old-aab")
        val targetReport = file("reports/report.json", "old-report")
        var cleanupFailureInjected = false
        val publisher = VerifiedArtifactPublisher { path ->
            if (!cleanupFailureInjected && path.fileName.toString().contains("-backup-")) {
                cleanupFailureInjected = true
                throw IOException("injected post-commit cleanup failure")
            }
            Files.deleteIfExists(path)
        }

        val result = publisher.publish(
            sourceBundle,
            sourceReport,
            targetBundle,
            targetReport,
        ) {
            "state-committed"
        }

        assertTrue(cleanupFailureInjected)
        assertEquals("state-committed", result)
        assertEquals("new-aab", targetBundle.readText())
        assertEquals("new-report", targetReport.readText())
        assertFalse(temporary.toFile().walkTopDown().any { it.name.contains(".hardening-tmp-") })
    }

    private fun file(relative: String, contents: String): Path = temporary.resolve(relative).also { path ->
        Files.createDirectories(path.parent)
        path.writeText(contents)
    }
}
