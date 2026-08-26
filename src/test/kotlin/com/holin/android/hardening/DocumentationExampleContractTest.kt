package com.holin.android.hardening

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DocumentationExampleContractTest {
    @Test
    fun `bilingual documentation publishes the complete consumer contract`() {
        val root = repositoryRoot()
        val chinese = requiredText(root.resolve("README.md"))
        val english = requiredText(root.resolve("README.en.md"))

        assertTrue(chinese.contains("[English](README.en.md)"), "Chinese README must link to English")
        assertTrue(english.contains("[Chinese](README.md)"), "English README must link to Chinese")
        REQUIRED_DOCUMENTATION_SNIPPETS.forEach { snippet ->
            assertTrue(chinese.contains(snippet), "Chinese README is missing: $snippet")
            assertTrue(english.contains(snippet), "English README is missing: $snippet")
        }
        REQUIRED_TASKS.forEach { task ->
            assertTrue(chinese.contains(task), "Chinese README is missing task $task")
            assertTrue(english.contains(task), "English README is missing task $task")
        }
    }

    @Test
    fun `neutral example resolves the extracted Maven binary without source substitution`() {
        val root = repositoryRoot()
        val example = root.resolve("examples/multi-module-consumer")
        REQUIRED_EXAMPLE_FILES.forEach { relative ->
            assertTrue(example.resolve(relative).exists(), "example is missing $relative")
        }
        REQUIRED_IGNORED_EXAMPLE_PATHS.forEach { relative ->
            assertTrue(isGitIgnored(root, relative), "example generated state is not ignored: $relative")
        }
        val settings = requiredText(example.resolve("settings.gradle.kts"))
        val rootBuild = requiredText(example.resolve("build.gradle.kts"))
        val mobileBuild = requiredText(example.resolve("mobile/build.gradle.kts"))
        val allBuildLogic = listOf(settings, rootBuild, mobileBuild).joinToString("\n")

        assertTrue(settings.contains("hardeningPluginRepo"), "example must accept the extracted Maven repository")
        assertTrue(settings.contains("include(\":mobile\", \":core\", \":media\")"), "example modules are incomplete")
        assertFalse(allBuildLogic.contains("includeBuild"), "example must not substitute plugin source")
        assertTrue(rootBuild.contains("id(\"com.holin.android.hardening\") version \"1.2.0\" apply false"))
        assertTrue(mobileBuild.contains("id(\"com.holin.android.hardening\")"))
        REQUIRED_EXAMPLE_SNIPPETS.forEach { snippet ->
            assertTrue(mobileBuild.contains(snippet), "mobile example is missing: $snippet")
        }
        listOf("com.example.demo", "project(\":core\")", "project(\":media\")").forEach { identity ->
            assertTrue(allBuildLogic.contains(identity), "example is missing neutral identity $identity")
        }
    }

    @Test
    fun `public documentation and example contain no sensitive or former identity content`() {
        val root = repositoryRoot()
        val example = root.resolve("examples/multi-module-consumer")
        val generatedRoots = listOf(
            example.resolve(".gradle"),
            example.resolve("mobile/build"),
            example.resolve(".hardening"),
        )
        val seeded = seedGeneratedFiles(generatedRoots)
        try {
            val files = trackedPublicFiles(root)
            seeded.forEach { generated ->
                assertFalse(generated.file in files, "untracked generated state entered the public-content scan")
            }
            val violations = files.flatMap { path ->
                val relative = root.relativize(path).toString().replace('\\', '/')
                val content = Files.readAllBytes(path).toString(Charsets.ISO_8859_1)
                FORBIDDEN_PATH_PARTS.filter { part -> relative.contains(part, true) }
                    .map { part -> "$relative -> path:$part" } +
                    FORBIDDEN_CONTENT.filter { text -> content.contains(text, true) }
                        .map { text -> "$relative -> content:$text" }
            }

            assertTrue(violations.isEmpty(), violations.joinToString(", ", "public content violations:\n"))
        } finally {
            seeded.asReversed().forEach(::removeGeneratedFile)
        }
    }

    private fun trackedPublicFiles(root: Path): List<Path> {
        val process = ProcessBuilder(
            "git",
            "-C",
            root.toString(),
            "ls-files",
            "-z",
            "--",
            "README.md",
            "README.en.md",
            "examples/multi-module-consumer",
        ).start()
        val output = process.inputStream.readAllBytes()
        val error = process.errorStream.bufferedReader().readText()
        check(process.waitFor() == 0) { "cannot enumerate tracked public content: $error" }
        return output.toString(Charsets.UTF_8)
            .split('\u0000')
            .filter(String::isNotEmpty)
            .map { relative -> root.resolve(relative).normalize() }
    }

    private fun seedGeneratedFiles(roots: List<Path>): List<SeededGeneratedFile> = roots.map { generatedRoot ->
        val rootExisted = Files.exists(generatedRoot)
        val probeDirectory = generatedRoot.resolve("task-4-contract-probe")
        val probe = probeDirectory.resolve("generated-state.bin")
        check(!Files.exists(probe)) { "generated-state regression probe already exists: $probe" }
        Files.createDirectories(probeDirectory)
        Files.writeString(probe, "generated and intentionally untracked\n")
        SeededGeneratedFile(generatedRoot, probeDirectory, probe, rootExisted)
    }

    private fun removeGeneratedFile(seeded: SeededGeneratedFile) {
        Files.deleteIfExists(seeded.file)
        Files.deleteIfExists(seeded.probeDirectory)
        if (!seeded.rootExisted && Files.isDirectory(seeded.generatedRoot)) {
            val empty = Files.list(seeded.generatedRoot).use { paths -> paths.findAny().isEmpty }
            if (empty) Files.delete(seeded.generatedRoot)
        }
    }

    private fun requiredText(path: Path): String {
        assertTrue(path.exists(), "required public file is missing: $path")
        return path.readText()
    }

    private fun isGitIgnored(root: Path, relative: String): Boolean = ProcessBuilder(
        "git",
        "-C",
        root.toString(),
        "check-ignore",
        "--quiet",
        "--",
        relative,
    ).start().waitFor() == 0

    private fun repositoryRoot(): Path {
        val candidates = listOf(Path.of("."), Path.of(".."))
            .map(Path::toAbsolutePath)
            .map(Path::normalize)
        return candidates.singleOrNull { candidate ->
            Files.isRegularFile(candidate.resolve("settings.gradle.kts")) &&
                Files.isDirectory(candidate.resolve("src/main/kotlin/com/holin/android/hardening"))
        } ?: error("cannot locate repository root from ${Path.of("").toAbsolutePath()}")
    }

    private companion object {
        val REQUIRED_DOCUMENTATION_SNIPPETS = listOf(
            "Gradle 8.10+",
            "AGP 8.8+",
            "JDK 17+",
            "Kotlin Android Plugin 2.3+",
            "androidHardening",
            "-PandroidHardening=true",
            "hardeningw",
            "hardeningw.ps1",
            "hardeningw.bat",
            "hardeningPluginRepo",
            "SHA256SUMS",
            "verification-metadata.xml",
            "includeBuild",
            "WebP",
            "Gson",
            "JNI",
            "JavaScript",
            "R8",
            "Retrace",
            "fixedSeed",
            "similarity",
            ".hardening/mappings",
            ".hardening/baselines",
            "build/outputs/hardening/<variant>",
            "build/reports/hardening/<variant>",
            "androidHardeningReferenceAab",
            "serial.set(providers.gradleProperty(\"androidHardeningDeviceSerial\"))",
            "applicationId.set(providers.gradleProperty(\"androidHardeningApplicationId\"))",
            "launchActivity.set(providers.gradleProperty(\"androidHardeningLaunchActivity\"))",
        )
        val REQUIRED_TASKS = listOf(
            "prepareHardeningDemoQa",
            "auditHardeningDemoQa",
            "verifyHardeningDemoQa",
            "archiveHardeningDemoQa",
            "hardeningBundleDemoQa",
            "hardeningAssembleDemoQa",
            "captureHardeningBaselineDemoQa",
            "compareHardeningDemoQa",
            "compareExternalHardeningDemoQa",
            "benchmarkHardeningDemoQa",
            "smokeHardeningDemoQa",
            "hardeningRunDemoQa",
            "assembleHardeningDemoQaUniversalApk",
            "assembleOrdinaryDemoQaUniversalApk",
        )
        val REQUIRED_EXAMPLE_FILES = listOf(
            "README.md",
            "settings.gradle.kts",
            "build.gradle.kts",
            "gradle.properties",
            "mobile/build.gradle.kts",
            "mobile/proguard-rules.pro",
            "mobile/hardening-preserve-exact.pro",
            "mobile/hardening-additional.pro",
            "mobile/src/main/AndroidManifest.xml",
            "mobile/src/demo/AndroidManifest.xml",
            "core/build.gradle.kts",
            "core/src/main/AndroidManifest.xml",
            "media/build.gradle.kts",
            "media/src/main/AndroidManifest.xml",
        )
        val REQUIRED_EXAMPLE_SNIPPETS = listOf(
            "providers.gradleProperty(\"androidHardening\")",
            "providers.gradleProperty(\"androidHardeningFixedSeed\")",
            "variants.include(\"demoQa\")",
            "module(\":mobile\")",
            "module(\":core\")",
            "module(\":media\")",
            "sourceSets.addAll(\"main\", \"demo\")",
            "src/demoResources/res",
            "webp {",
            "include(\"src/demoResources/res/drawable/**/*.webp\")",
            "exclude(\"src/demoResources/res/drawable/no_rewrite/**/*.webp\")",
            "sourceFiles.from(\"proguard-rules.pro\")",
            "preserveExactRules.from(\"hardening-preserve-exact.pro\")",
            "additionalRules.from(\"hardening-additional.pro\")",
            "storeDirectory.set(rootProject.layout.projectDirectory.dir(\".hardening/mappings\"))",
            "reuseVariantSigningConfig.set(true)",
            "DEMO_SIGNING_STORE_FILE",
            "verifyCompatibility.set(true)",
            "baselineFile.set(rootProject.layout.projectDirectory.file(\"legacy/legacy-plugin-baseline.json\"))",
            "plugin(\"neutralLegacy\")",
            "autoMigrateLegacyState.set(false)",
        )
        val REQUIRED_IGNORED_EXAMPLE_PATHS = listOf(
            "examples/multi-module-consumer/.gradle/task-cache.bin",
            "examples/multi-module-consumer/mobile/.gradle/task-cache.bin",
            "examples/multi-module-consumer/.gradle-home/caches/modules.bin",
            "examples/multi-module-consumer/.kotlin/sessions/session.bin",
            "examples/multi-module-consumer/.idea/workspace.xml",
            "examples/multi-module-consumer/.hardening/mappings/demo/state.bin",
            "examples/multi-module-consumer/local.properties",
            "examples/multi-module-consumer/mobile/build/generated/output.bin",
            "examples/multi-module-consumer/mobile/.cxx/qa/metadata.bin",
            "examples/multi-module-consumer/mobile/.externalNativeBuild/qa/metadata.bin",
            "examples/multi-module-consumer/mobile/out/generated/output.bin",
            "examples/multi-module-consumer/captures/layout.png",
        )
        val FORBIDDEN_PATH_PARTS = listOf(
            ".jks",
            ".keystore",
            ".p12",
            ".pfx",
            ".apk",
            ".aab",
            ".apks",
            ".dex",
            ".hardening/",
            ".gradle/",
            ".gradle-home/",
            "/build/",
            "mapping.txt",
            "baseline.json",
        )
        val FORBIDDEN_CONTENT = listOf(
            listOf("single", "link").joinToString(""),
            "lu" + "mo",
            "hu" + "sh",
            "joy" + "happier",
            listOf("/Users/", "Zhu", "anz1").joinToString(""),
            "storePassword = \"",
            "keyPassword = \"",
        )
    }

    private data class SeededGeneratedFile(
        val generatedRoot: Path,
        val probeDirectory: Path,
        val file: Path,
        val rootExisted: Boolean,
    )
}
