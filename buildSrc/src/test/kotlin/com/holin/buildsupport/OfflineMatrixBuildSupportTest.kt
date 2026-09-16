package com.holin.buildsupport

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class OfflineMatrixBuildSupportTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `reviewed license policy maps known groups and rejects unknown groups`() {
        assertEquals("Apache-2.0", OfflineLicensePolicy.licenseFor("com.android.tools.build"))
        assertEquals("BSD-3-Clause", OfflineLicensePolicy.licenseFor("com.google.protobuf"))
        assertEquals("Apache-2.0", OfflineLicensePolicy.licenseFor("io.netty"))

        assertFailsWith<IllegalStateException> {
            OfflineLicensePolicy.licenseFor("invalid.unreviewed")
        }
    }

    @Test
    fun `normalized POM escapes XML and renders classifier type and runtime scope`() {
        val dependencyFile = temporary.resolve("dependency.zip")
        Files.writeString(dependencyFile, "artifact")
        val dependency = OfflineMatrixArtifact(
            "com.example&tools",
            "runtime<api>",
            "1.0\"beta",
            "host&debug",
            "zip",
            dependencyFile,
        )

        val pom = NormalizedMavenPom.render("com.host&group", "plugin.gradle.plugin", "2<3", listOf(dependency))

        assertContains(pom, "<groupId>com.host&amp;group</groupId>")
        assertContains(pom, "<artifactId>runtime&lt;api&gt;</artifactId>")
        assertContains(pom, "<version>1.0&quot;beta</version>")
        assertContains(pom, "<classifier>host&amp;debug</classifier>")
        assertContains(pom, "<type>zip</type>")
        assertContains(pom, "<scope>runtime</scope>")
        assertContains(pom, "<packaging>pom</packaging>")
    }

    @Test
    fun `Gradle distribution discovery selects a complete home and rejects incomplete distributions`() {
        val gradleUserHome = temporary.resolve("gradle-user-home")
        val incomplete = gradleUserHome.resolve("wrapper/dists/gradle-8.13-bin/a/gradle-8.13")
        Files.createDirectories(incomplete)
        val complete = gradleUserHome.resolve("wrapper/dists/gradle-8.13-bin/b/gradle-8.13")
        Files.createDirectories(complete.resolve("bin"))
        Files.writeString(complete.resolve("bin/gradle"), "launcher")

        assertEquals(complete, GradleDistributionLocator.findGradleHome(gradleUserHome, "8.13"))
        assertFailsWith<IllegalArgumentException> {
            GradleDistributionLocator.findGradleHome(gradleUserHome, "8.11.1")
        }
        val incompleteOnly = gradleUserHome.resolve("wrapper/dists/gradle-8.12-bin/a/gradle-8.12")
        Files.createDirectories(incompleteOnly)
        assertFailsWith<IllegalStateException> {
            GradleDistributionLocator.findGradleHome(gradleUserHome, "8.12")
        }
    }

    @Test
    fun `Gradle distribution discovery finds a provisioner managed home`() {
        val gradleUserHome = temporary.resolve("gradle-user-home")
        val managed = gradleUserHome.resolve("holin-hardening/distributions/8.11.1/gradle-8.11.1")
        Files.createDirectories(managed.resolve("bin"))
        Files.writeString(managed.resolve("bin/gradle"), "launcher")

        assertEquals(managed, GradleDistributionLocator.findGradleHome(gradleUserHome, "8.11.1"))
    }

    @Test
    fun `offline matrix assembler writes a complete portable consumer fixture`() {
        val portableArchive = temporary.resolve("portable.zip")
        zip(
            portableArchive,
            mapOf(
                "repository/com/holin/android/hardening/hardening-gradle-plugin/1.3.0/" +
                    "hardening-gradle-plugin-1.3.0.jar" to "portable-plugin",
            ),
        )
        val gradleHome = temporary.resolve("gradle-8.13")
        Files.createDirectories(gradleHome.resolve("bin"))
        Files.writeString(gradleHome.resolve("bin/gradle"), "launcher")
        Files.createDirectories(gradleHome.resolve("lib"))
        Files.writeString(gradleHome.resolve("lib/gradle.jar"), "runtime")
        val artifactRoot = temporary.resolve("artifacts")
        Files.createDirectories(artifactRoot)
        val agp = artifact(artifactRoot, "gradle.jar", "agp")
        val kotlinPlugin = artifact(artifactRoot, "kotlin-gradle-plugin.jar", "kotlin")
        val utility = artifact(artifactRoot, "utility.jar", "utility")
        val artifacts = listOf(
            OfflineMatrixArtifact("com.android.tools.build", "gradle", "8.13.2", null, "jar", agp),
            OfflineMatrixArtifact(
                "org.jetbrains.kotlin",
                "kotlin-gradle-plugin",
                "2.3.0",
                "gradle813",
                "jar",
                kotlinPlugin,
            ),
            OfflineMatrixArtifact("com.google.guava", "utility", "1.0", null, "jar", utility),
        )
        val row = OfflineMatrixInput(
            "agp-8.13.2",
            "8.13.2",
            "8.13",
            "2.3.0",
            "8.13.2-aapt2",
            "31.13.2",
            gradleHome,
            artifacts,
            mapOf(
                "com.android.tools.build:gradle:8.13.2" to setOf("com.google.guava:utility:1.0"),
            ),
        )
        val staging = temporary.resolve("staging")
        val extraction = temporary.resolve("portable-extracted")

        OfflineMatrixAssembler.assemble(staging, extraction, portableArchive, "1.3.0", listOf(row))

        assertTrue(Files.mismatch(portableArchive, staging.resolve("portable/portable.zip")) == -1L)
        assertTrue(Files.isRegularFile(staging.resolve("fixture-templates/settings.gradle.template")))
        assertContains(
            Files.readString(staging.resolve("fixture-templates/build.gradle.template")),
                "id 'com.holin.android.hardening' version '1.3.0' apply false",
        )
        assertTrue(
            Files.isRegularFile(
                staging.resolve(
                    "matrix/agp-8.13.2/repository/com/android/application/" +
                        "com.android.application.gradle.plugin/8.13.2/" +
                        "com.android.application.gradle.plugin-8.13.2.pom",
                ),
            ),
        )
        assertTrue(
            Files.isRegularFile(
                staging.resolve(
                    "matrix/agp-8.13.2/repository/org/jetbrains/kotlin/android/" +
                        "org.jetbrains.kotlin.android.gradle.plugin/2.3.0/" +
                        "org.jetbrains.kotlin.android.gradle.plugin-2.3.0.pom",
                ),
            ),
        )
        assertContains(
            Files.readString(
                staging.resolve(
                    "matrix/agp-8.13.2/repository/com/android/tools/build/gradle/8.13.2/gradle-8.13.2.pom",
                ),
            ),
            "<artifactId>utility</artifactId>",
        )
        assertContains(
            Files.readString(staging.resolve("matrix/agp-8.13.2/verification-metadata.xml")),
                "name=\"hardening-gradle-plugin\" version=\"1.3.0\"",
        )
        assertContains(
            Files.readString(staging.resolve("matrix/agp-8.13.2/THIRD_PARTY_LICENSES.txt")),
            "com.android.tools.build:gradle:8.13.2 | Apache-2.0 |",
        )
        assertTrue(Files.isRegularFile(staging.resolve("matrix/agp-8.13.2/gradle/gradle-8.13/lib/gradle.jar")))
        assertContains(Files.readString(staging.resolve("MATRIX-MANIFEST.txt")), "available|agp=8.13.2")
        assertContains(Files.readString(staging.resolve("FIXTURE-MANIFEST.txt")), "portableArchive=portable/portable.zip")
    }

    @Test
    fun `offline matrix assembler rejects duplicate portable entries`() {
        val portableArchive = temporary.resolve("duplicate-portable.zip")
        rawZip(
            portableArchive,
            listOf(
                "repository/com/example/plugin/1.0/plugin-1.0.jar" to "first".toByteArray(),
                "repository/com/example/plugin/1.0/plugin-1.0.jar" to "second".toByteArray(),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            OfflineMatrixAssembler.assemble(
                temporary.resolve("duplicate-staging"),
                temporary.resolve("duplicate-extraction"),
                portableArchive,
                "1.3.0",
                emptyList(),
            )
        }
    }

    @Test
    fun `offline matrix assembler rejects traversal and absolute portable entries`() {
        listOf("../escape.txt", "/absolute.txt").forEachIndexed { index, entryName ->
            val portableArchive = temporary.resolve("traversal-portable-$index.zip")
            rawZip(portableArchive, listOf(entryName to "escape".toByteArray()))

            assertFailsWith<IllegalArgumentException> {
                OfflineMatrixAssembler.assemble(
                    temporary.resolve("traversal-staging-$index"),
                    temporary.resolve("traversal-extraction-$index"),
                    portableArchive,
                    "1.3.0",
                    emptyList(),
                )
            }
        }
    }

    private fun artifact(root: Path, name: String, content: String): Path = root.resolve(name).also { path ->
        Files.writeString(path, content)
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

    private fun rawZip(output: Path, entries: List<Pair<String, ByteArray>>) {
        val bytes = java.io.ByteArrayOutputStream()
        val records = entries.map { (name, contents) ->
            val nameBytes = name.toByteArray()
            val checksum = CRC32().also { crc -> crc.update(contents) }.value
            val offset = bytes.size()
            littleEndian32(bytes, 0x04034b50)
            littleEndian16(bytes, 20)
            littleEndian16(bytes, 0)
            littleEndian16(bytes, 0)
            littleEndian16(bytes, 0)
            littleEndian16(bytes, 0)
            littleEndian32(bytes, checksum)
            littleEndian32(bytes, contents.size.toLong())
            littleEndian32(bytes, contents.size.toLong())
            littleEndian16(bytes, nameBytes.size)
            littleEndian16(bytes, 0)
            bytes.write(nameBytes)
            bytes.write(contents)
            RawZipRecord(nameBytes, contents.size, checksum, offset)
        }
        val centralDirectoryOffset = bytes.size()
        records.forEach { record ->
            littleEndian32(bytes, 0x02014b50)
            littleEndian16(bytes, 20)
            littleEndian16(bytes, 20)
            littleEndian16(bytes, 0)
            littleEndian16(bytes, 0)
            littleEndian16(bytes, 0)
            littleEndian16(bytes, 0)
            littleEndian32(bytes, record.checksum)
            littleEndian32(bytes, record.size.toLong())
            littleEndian32(bytes, record.size.toLong())
            littleEndian16(bytes, record.name.size)
            littleEndian16(bytes, 0)
            littleEndian16(bytes, 0)
            littleEndian16(bytes, 0)
            littleEndian16(bytes, 0)
            littleEndian32(bytes, 0)
            littleEndian32(bytes, record.offset.toLong())
            bytes.write(record.name)
        }
        val centralDirectorySize = bytes.size() - centralDirectoryOffset
        littleEndian32(bytes, 0x06054b50)
        littleEndian16(bytes, 0)
        littleEndian16(bytes, 0)
        littleEndian16(bytes, records.size)
        littleEndian16(bytes, records.size)
        littleEndian32(bytes, centralDirectorySize.toLong())
        littleEndian32(bytes, centralDirectoryOffset.toLong())
        littleEndian16(bytes, 0)
        Files.write(output, bytes.toByteArray())
    }

    private fun littleEndian16(output: java.io.ByteArrayOutputStream, value: Int) {
        output.write(value and 0xff)
        output.write((value ushr 8) and 0xff)
    }

    private fun littleEndian32(output: java.io.ByteArrayOutputStream, value: Long) {
        repeat(4) { offset -> output.write(((value ushr (offset * 8)) and 0xff).toInt()) }
    }

    private data class RawZipRecord(
        val name: ByteArray,
        val size: Int,
        val checksum: Long,
        val offset: Int,
    )
}
