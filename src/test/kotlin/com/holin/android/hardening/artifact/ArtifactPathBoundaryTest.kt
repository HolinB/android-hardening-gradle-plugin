package com.holin.android.hardening.artifact

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.io.TempDir

class ArtifactPathBoundaryTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `output parent is created only below the trusted boundary`() {
        val boundary = temporary.resolve("build")
        val output = boundary.resolve("outputs/hardening/app.aab")

        ArtifactPathBoundary(boundary).prepareOutput(output)

        assertTrue(Files.isDirectory(output.parent))
    }

    @Test
    fun `symlinked output ancestor is rejected without writing outside boundary`() {
        assumeTrue(!System.getProperty("os.name").startsWith("Windows", ignoreCase = true))
        val boundary = temporary.resolve("build").also(Files::createDirectories)
        val outside = temporary.resolve("outside").also(Files::createDirectories)
        Files.createSymbolicLink(boundary.resolve("outputs"), outside)
        val output = boundary.resolve("outputs/hardening/app.aab")

        assertFailsWith<IllegalArgumentException> {
            ArtifactPathBoundary(boundary).prepareOutput(output)
        }

        assertTrue(Files.notExists(outside.resolve("hardening/app.aab")))
    }

    @Test
    fun `input symlink is rejected even when its target is below boundary`() {
        assumeTrue(!System.getProperty("os.name").startsWith("Windows", ignoreCase = true))
        val boundary = temporary.resolve("build").also(Files::createDirectories)
        val real = boundary.resolve("ordinary.aab").also { it.writeText("bundle") }
        val link = boundary.resolve("linked.aab")
        Files.createSymbolicLink(link, real)

        assertFailsWith<IllegalArgumentException> {
            ArtifactPathBoundary(boundary).requireInput(link)
        }
    }

    @Test
    fun `path outside trusted boundary is rejected`() {
        val boundary = temporary.resolve("build").also(Files::createDirectories)
        val outside = temporary.resolve("outside/app.aab")

        assertFailsWith<IllegalArgumentException> {
            ArtifactPathBoundary(boundary).prepareOutput(outside)
        }
    }
}
