package com.holin.android.hardening

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PortablePublicationContractTest {
    @Test
    fun `tracked public content contains no project or user identities`() {
        val root = repositoryRoot()
        val trackedFiles = ProcessBuilder("git", "-C", root.toString(), "ls-files", "-z")
            .start()
            .let { process ->
                val output = process.inputStream.readAllBytes()
                assertEquals(0, process.waitFor(), process.errorStream.bufferedReader().readText())
                output.toString(Charsets.UTF_8).split('\u0000').filter(String::isNotEmpty)
            }
        val violations = trackedFiles.flatMap { relativePath ->
            val content = Files.readAllBytes(root.resolve(relativePath)).toString(Charsets.ISO_8859_1)
            FORBIDDEN_PUBLIC_CONTENT.filter { forbidden -> content.contains(forbidden, true) }
                .map { forbidden -> "$relativePath -> $forbidden" }
        }

        assertTrue(
            violations.isEmpty(),
            violations.joinToString(prefix = "fixed identity remains in tracked public content:\n"),
        )
    }

    @Test
    fun `portable publication exposes the fixed local delivery contract`() {
        val root = repositoryRoot()
        val buildLogic = root.resolve("build.gradle.kts").readText()
        val settings = root.resolve("settings.gradle.kts").readText()

        REQUIRED_BUILD_LOGIC_SNIPPETS.forEach { snippet ->
            assertTrue(buildLogic.contains(snippet), "missing portable publication contract: $snippet")
        }
        REQUIRED_SETTINGS_SNIPPETS.forEach { snippet ->
            assertTrue(settings.contains(snippet), "missing binary plugin resolution contract: $snippet")
        }
        assertTrue(root.resolve("LICENSE").exists(), "portable plugin LICENSE is missing")
        assertTrue(root.resolve("NOTICE").exists(), "portable plugin NOTICE is missing")
        assertTrue(root.resolve("hardeningw").exists(), "POSIX hardening launcher is missing")
        assertTrue(root.resolve("hardeningw.ps1").exists(), "PowerShell hardening launcher is missing")
        assertTrue(root.resolve("hardeningw.bat").exists(), "Windows hardening launcher is missing")
        assertTrue(root.resolve("bootstrap/HardeningLauncher.java").exists(), "portable launcher source is missing")
        val shippedMainSources = Files.walk(root.resolve("src/main"))
            .use { paths ->
                paths.filter { path -> Files.isRegularFile(path) }
                    .map { path -> path to path.readText() }
                    .toList()
            }
        val shippedPublicationMetadata = listOf(
            root.resolve("build.gradle.kts") to buildLogic,
            root.resolve("LICENSE") to root.resolve("LICENSE").readText(),
            root.resolve("NOTICE") to root.resolve("NOTICE").readText(),
        )
        val portableContent = shippedMainSources + shippedPublicationMetadata
        val forbiddenIdentifiers = portableContent.flatMap { (path, content) ->
            val forbidden = FORBIDDEN_PORTABLE_IDENTIFIERS.filter(content::contains) +
                LEGACY_PORTABLE_IDENTIFIERS.filter { identifier -> content.contains(identifier, true) }
            forbidden.distinct().map { identifier ->
                "${root.relativize(path)} -> $identifier"
            }
        }
        assertFalse(
            forbiddenIdentifiers.isNotEmpty(),
            forbiddenIdentifiers.joinToString(prefix = "fixed identity remains in portable content:\n"),
        )
        assertTrue(
            Files.isDirectory(root.resolve("src/main/kotlin/com/holin/android/hardening")),
            "shipped implementation package is not migrated",
        )
        assertFalse(
            buildLogic.contains("implementation(\"com.android.tools.build:builder:8.13.2\")"),
            "AGP's R8 carrier must be supplied by the strictly matched consumer AGP",
        )
        assertFalse(
            buildLogic.contains("https://plugins.gradle.org") ||
                buildLogic.contains("publishPlugins") ||
                buildLogic.contains("signing {") ||
                buildLogic.contains("credentials {") ,
            "portable publication must remain local and credential-free",
        )
        assertTrue(
            buildLogic.contains("include(\"com/holin/android/hardening/hardening-gradle-plugin/\${project.version}/**\")") &&
                buildLogic.contains("include(\"com/holin/android/hardening/com.holin.android.hardening.gradle.plugin/\${project.version}/**\")"),
            "portable staging must copy only the current implementation and marker coordinates",
        )
        assertTrue(
            buildLogic.contains("portable staging contains a legacy hardening identity"),
            "portable staging verification must reject a seeded legacy marker",
        )
    }

    @Test
    fun `portable package emits and documents its outer checksum sidecar`() {
        val root = repositoryRoot()
        val buildLogic = root.resolve("build.gradle.kts").readText()
        val readme = root.resolve("README.md").readText()
        val englishReadme = root.resolve("README.en.md").readText()
        val checksumName = "hardening-gradle-plugin-1.2.0-portable-maven.zip.sha256"

        assertTrue(
            buildLogic.contains("hardening-gradle-plugin-\${project.version}-portable-maven.zip.sha256"),
            "portable outer checksum output is not declared",
        )
        assertTrue(
            buildLogic.contains("outputs.file(portableArchiveChecksum)"),
            "portable package task does not own the checksum sidecar",
        )
        assertTrue(
            buildLogic.contains("require(actualChecksum == expectedChecksum)"),
            "portable verification does not validate the checksum sidecar",
        )
        assertTrue(readme.contains(checksumName), "Chinese release instructions omit the checksum sidecar")
        assertTrue(englishReadme.contains(checksumName), "English release instructions omit the checksum sidecar")
    }

    private fun repositoryRoot(): Path {
        val candidates = listOf(Path.of("."), Path.of(".."))
            .map(Path::toAbsolutePath)
            .map(Path::normalize)
        return candidates.singleOrNull {
            Files.isRegularFile(it.resolve("settings.gradle.kts")) &&
                Files.isRegularFile(it.resolve("build.gradle.kts")) &&
                Files.isDirectory(it.resolve("src/main/kotlin/com/holin/android/hardening"))
        } ?: error("cannot locate repository root from ${Path.of("").toAbsolutePath()}")
    }

    private companion object {
        val REQUIRED_BUILD_LOGIC_SNIPPETS = listOf(
            "`maven-publish`",
            "group = \"com.holin.android.hardening\"",
            "version = \"1.2.0\"",
            "artifactId = \"hardening-gradle-plugin\"",
            "id = \"com.holin.android.hardening\"",
            "implementationClass = \"com.holin.android.hardening.AndroidHardeningPlugin\"",
            "packagePortableHardeningPlugin",
            "verifyPortableHardeningPlugin",
            "checkHardeningEnvironment",
            "prepareOfflineTestKitEnvironment",
            "publishAllPublicationsToPortableRepository",
            "portableRuntimeArtifacts",
            "THIRD_PARTY_LICENSES.txt",
            "compileOnly(\"com.android.tools.build:builder:8.8.0\")",
            "testImplementation(\"com.android.tools.build:builder:8.13.2\")",
            "isPreserveFileTimestamps = false",
            "isReproducibleFileOrder = true",
        )
        val REQUIRED_SETTINGS_SNIPPETS = listOf(
            "rootProject.name = \"android-hardening-gradle-plugin\"",
            "gradlePluginPortal()",
            "google()",
            "mavenCentral()",
        )

        val FORBIDDEN_PORTABLE_IDENTIFIERS = listOf(
            "HardeningOwnedModules",
            "SourceSetName",
            "\":app\"",
            "\":core\"",
            "\":compress\"",
            "\":selector\"",
            "\":ucrop\"",
        )
        val LEGACY_PORTABLE_IDENTIFIERS = listOf("com.legacy.vendor", "com/legacy/vendor")
        val FORBIDDEN_PUBLIC_CONTENT = listOf(
            listOf("single", "link").joinToString(""),
            "lu" + "mo",
            "hu" + "sh",
            "joy" + "happier",
            listOf("/Users/", "Zhu", "anz1").joinToString(""),
        )
    }
}
