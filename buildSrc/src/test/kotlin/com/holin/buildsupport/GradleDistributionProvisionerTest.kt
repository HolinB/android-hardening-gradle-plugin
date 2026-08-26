package com.holin.buildsupport

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class GradleDistributionProvisionerTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `existing wrapper distribution is reused without downloading`() {
        val home = temporary.resolve("gradle-home")
        val distribution = home.resolve("wrapper/dists/gradle-8.13-bin/cache/gradle-8.13")
        Files.createDirectories(distribution.resolve("bin"))
        Files.writeString(distribution.resolve("bin/gradle"), "launcher")
        val provisioner = GradleDistributionProvisioner(
            DistributionDownloader { _, _ -> error("download must not run") },
        )

        val resolved = provisioner.ensure(home, GradleDistributionSpec("8.13", "0".repeat(64)), true)

        assertEquals(distribution, resolved)
    }

    @Test
    fun `missing distribution is downloaded verified and extracted into managed cache`() {
        val archive = temporary.resolve("gradle.zip")
        zip(
            archive,
            mapOf(
                "gradle-8.11.1/bin/gradle" to "launcher",
                "gradle-8.11.1/lib/gradle.jar" to "runtime",
            ),
        )
        val provisioner = GradleDistributionProvisioner(
            DistributionDownloader { _, target -> Files.copy(archive, target) },
        )

        val resolved = provisioner.ensure(
            temporary.resolve("gradle-home"),
            GradleDistributionSpec("8.11.1", sha256(archive)),
            false,
        )

        assertTrue(Files.isRegularFile(resolved.resolve("bin/gradle")))
        assertTrue(Files.isRegularFile(resolved.resolve("lib/gradle.jar")))
    }

    @Test
    fun `offline missing distribution reports the exact version`() {
        val failure = assertFailsWith<IllegalStateException> {
            GradleDistributionProvisioner().ensure(
                temporary.resolve("gradle-home"),
                GradleDistributionSpec("8.10.2", "0".repeat(64)),
                true,
            )
        }

        assertContains(failure.message.orEmpty(), "Gradle 8.10.2")
        assertContains(failure.message.orEmpty(), "offline")
    }

    @Test
    fun `download checksum mismatch does not publish a distribution`() {
        val archive = temporary.resolve("gradle.zip")
        zip(archive, mapOf("gradle-8.13/bin/gradle" to "launcher"))
        val home = temporary.resolve("gradle-home")
        val provisioner = GradleDistributionProvisioner(
            DistributionDownloader { _, target -> Files.copy(archive, target) },
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            provisioner.ensure(home, GradleDistributionSpec("8.13", "0".repeat(64)), false)
        }

        assertContains(failure.message.orEmpty(), "checksum")
        assertTrue(Files.notExists(home.resolve("holin-hardening/distributions/8.13/gradle-8.13")))
    }

    @Test
    fun `online preparation repairs an incomplete managed distribution`() {
        val archive = temporary.resolve("gradle.zip")
        zip(
            archive,
            mapOf(
                "gradle-8.11.1/bin/gradle" to "launcher",
                "gradle-8.11.1/lib/gradle.jar" to "runtime",
            ),
        )
        val home = temporary.resolve("gradle-home")
        val managed = home.resolve("holin-hardening/distributions/8.11.1/gradle-8.11.1")
        Files.createDirectories(managed)
        Files.writeString(managed.resolve("partial.txt"), "incomplete")
        val provisioner = GradleDistributionProvisioner(
            DistributionDownloader { _, target -> Files.copy(archive, target) },
        )

        val resolved = provisioner.ensure(
            home,
            GradleDistributionSpec("8.11.1", sha256(archive)),
            false,
        )

        assertEquals(managed, resolved)
        assertTrue(Files.isRegularFile(resolved.resolve("bin/gradle")))
        assertTrue(Files.notExists(resolved.resolve("partial.txt")))
    }

    private fun zip(output: Path, entries: Map<String, String>) {
        ZipOutputStream(Files.newOutputStream(output)).use { zip ->
            entries.forEach { (name, contents) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(contents.toByteArray())
                zip.closeEntry()
            }
        }
    }

    private fun sha256(path: Path): String = MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path))
        .joinToString("") { byte -> "%02x".format(byte) }
}
