package com.holin.android.hardening

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.io.path.exists
import kotlin.io.path.isExecutable
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings

class RepositoryAutomationContractTest {
    @Test
    fun `wrapper distribution and jar are checksum pinned and verified offline`() {
        val root = repositoryRoot()
        val properties = requiredText(root.resolve("gradle/wrapper/gradle-wrapper.properties"))
        val checksum = requiredText(root.resolve("gradle/wrapper/gradle-wrapper.jar.sha256"))
        val wrapper = root.resolve("gradle/wrapper/gradle-wrapper.jar")
        val verifier = root.resolve("scripts/verify-gradle-wrapper.sh")

        assertTrue(
            properties.lineSequence().any { line -> line == "distributionSha256Sum=$GRADLE_DISTRIBUTION_SHA256" },
            "Gradle distribution checksum is not pinned",
        )
        assertTrue(
            properties.lineSequence().any { line -> line == GRADLE_DISTRIBUTION_URL },
            "Gradle distribution URL is not pinned to 8.13",
        )
        assertEquals("$GRADLE_WRAPPER_JAR_SHA256  gradle/wrapper/gradle-wrapper.jar\n", checksum)
        assertTracked(root, "gradle/wrapper/gradle-wrapper.jar.sha256")
        assertEquals(GRADLE_WRAPPER_JAR_SHA256, sha256(wrapper))
        assertTrue(verifier.exists(), "wrapper verification script is missing")
        assertTrue(verifier.isExecutable(), "wrapper verification script must be executable")
        val script = verifier.readText()
        assertFalse(Regex("(?i)\\b(curl|wget)\\b").containsMatchIn(script), "wrapper verification must be offline")

        val process = ProcessBuilder(verifier.toString())
            .directory(root.toFile())
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        assertEquals(0, process.waitFor(), output)
        assertTrue(output.contains("Gradle wrapper JAR checksum verified"), output)
    }

    @Test
    fun `ordinary CI verifies source binary consumption and deterministic portable publication`() {
        val workflow = workflow("ci.yml")

        assertEquals(setOf("push", "pull_request"), workflow.triggers.keys)
        assertLeastPrivilege(workflow)
        assertEquals(true, workflow.concurrency["cancel-in-progress"])
        assertEquals(60, workflow.job["timeout-minutes"])
        assertPinnedSetup(workflow.steps)
        assertRuns(
            workflow.steps,
            "./scripts/verify-gradle-wrapper.sh",
            "./gradlew --no-daemon checkHardeningEnvironment check verifyPortableHardeningPlugin",
            "./gradlew --no-daemon --rerun-tasks packagePortableHardeningPlugin verifyPortableHardeningPlugin",
            "cp build/distributions/hardening-gradle-plugin-1.2.0-portable-maven.zip \"\$RUNNER_TEMP/portable-first.zip\"",
            "cmp --silent \"\$RUNNER_TEMP/portable-first.zip\" build/distributions/hardening-gradle-plugin-1.2.0-portable-maven.zip",
        )
        val forcedRebuilds = workflow.commands.count { command ->
            command == "./gradlew --no-daemon --rerun-tasks packagePortableHardeningPlugin verifyPortableHardeningPlugin"
        }
        assertEquals(2, forcedRebuilds, "ordinary CI must force two portable ZIP builds")
        val root = repositoryRoot()
        val buildLogic = requiredText(root.resolve("build.gradle.kts"))
        assertTrue(
            buildLogic.contains("tasks.check {\n    dependsOn(functionalTestTask)\n}"),
            "check must retain the full functional TestKit lifecycle",
        )
        val binaryFixture = requiredText(
            root.resolve(
                "src/functionalTest/kotlin/com/holin/android/hardening/PortableBinaryConsumerFunctionalTest.kt",
            ),
        )
        assertTrue(binaryFixture.contains("portable.offline.testkit.archive"), "binary consumer archive contract is missing")
        assertTrue(
            binaryFixture.contains("assertFalse(settings.contains(\"includeBuild\")"),
            "binary consumer fixture must reject source substitution",
        )
        assertForbiddenOperationsAbsent(workflow)
    }

    @Test
    fun `forbidden operation matcher rejects suffixed task names and release commands`() {
        val forbidden = listOf(
            "./gradlew installDebug",
            "./gradlew hardeningRunRelease",
            "./gradlew smokeHardeningDemoQa",
            "./gradlew notifySlack",
            "./gradlew uploadArchives",
            "./gradlew publish",
            "adb devices",
            "gh release upload v1.2.0 plugin.zip",
            "git tag v1.2.0",
        )

        assertEquals(forbidden, forbiddenCommands(forbidden))
    }

    @Test
    fun `offline workflow prepares online then rebuilds and compares the complete kit locally`() {
        val workflow = workflow("offline-testkit.yml")

        assertEquals(setOf("workflow_dispatch", "schedule"), workflow.triggers.keys)
        val schedule = workflow.triggers["schedule"].listValue()
        assertTrue(schedule.isNotEmpty(), "offline workflow schedule is missing")
        assertTrue(schedule.all { item -> item.mapValue().keys == setOf("cron") })
        assertLeastPrivilege(workflow)
        assertEquals(false, workflow.concurrency["cancel-in-progress"])
        assertEquals(240, workflow.job["timeout-minutes"])
        assertPinnedSetup(workflow.steps)
        assertRuns(
            workflow.steps,
            "./scripts/verify-gradle-wrapper.sh",
            "./gradlew --no-daemon prepareOfflineTestKitEnvironment",
            "./gradlew --offline --no-daemon --rerun-tasks packageOfflineHardeningTestKit verifyOfflineHardeningTestKit",
            "cp build/distributions/hardening-gradle-plugin-1.2.0-offline-testkit.zip \"\$RUNNER_TEMP/offline-testkit-first.zip\"",
            "cmp --silent \"\$RUNNER_TEMP/offline-testkit-first.zip\" build/distributions/hardening-gradle-plugin-1.2.0-offline-testkit.zip",
        )
        val localRebuilds = workflow.commands.count { command ->
            command ==
                "./gradlew --offline --no-daemon --rerun-tasks packageOfflineHardeningTestKit verifyOfflineHardeningTestKit"
        }
        assertEquals(2, localRebuilds, "offline workflow must perform two forced local rebuilds")
        assertForbiddenOperationsAbsent(workflow)
    }

    private fun assertLeastPrivilege(workflow: Workflow) {
        assertEquals(mapOf("contents" to "read"), workflow.root.mapValue("permissions").stringMap())
        assertFalse(workflow.job.containsKey("permissions"), "job must not broaden token permissions")
        val serialized = workflow.source.lowercase()
        assertFalse("secrets." in serialized, "workflow must not consume repository secrets")
    }

    private fun assertPinnedSetup(steps: List<Map<String, Any?>>) {
        val actions = steps.mapNotNull { step -> step["uses"] as? String }
        assertEquals(
            listOf(
                "actions/checkout@v4",
                "actions/setup-java@v4",
                "gradle/actions/wrapper-validation@v4",
            ),
            actions,
            "workflow action allowlist changed",
        )
        val checkout = steps.single { step -> step["uses"] == "actions/checkout@v4" }.mapValue("with")
        assertEquals(false, checkout["persist-credentials"], "checkout credentials must not persist")
        val java = steps.single { step -> step["uses"] == "actions/setup-java@v4" }.mapValue("with")
        assertEquals("temurin", java["distribution"])
        assertEquals("17", java["java-version"].toString())
    }

    private fun assertRuns(steps: List<Map<String, Any?>>, vararg requiredCommands: String) {
        val commands = steps.flatMap(::commands)
        requiredCommands.forEach { command ->
            assertTrue(command in commands, "workflow is missing exact command: $command")
        }
    }

    private fun assertForbiddenOperationsAbsent(workflow: Workflow) {
        val uses = workflow.steps.mapNotNull { step -> step["uses"] as? String }
        assertTrue(uses.none { action -> action.startsWith("actions/upload-artifact@") }, "artifact upload is forbidden")
        val violations = forbiddenCommands(workflow.commands)
        assertTrue(violations.isEmpty(), violations.joinToString(prefix = "forbidden workflow commands:\n"))
        assertFalse("actions/create-release" in workflow.source, "workflow must not create a release")
    }

    private fun forbiddenCommands(commands: List<String>): List<String> = commands.filter { command ->
        val normalized = command.lowercase()
        FORBIDDEN_COMMAND_SNIPPETS.any(normalized::contains)
    }

    private fun workflow(name: String): Workflow {
        val source = requiredText(repositoryRoot().resolve(".github/workflows/$name"))
        val root = Load(LoadSettings.builder().build()).loadFromString(source).mapValue()
        val triggers = root.mapValue("on")
        val jobs = root.mapValue("jobs")
        val job = jobs.values.single().mapValue()
        val steps = job.listValue("steps").map { value -> value.mapValue() }
        return Workflow(source, root, triggers, root.mapValue("concurrency"), job, steps)
    }

    private fun commands(step: Map<String, Any?>): List<String> = (step["run"] as? String)
        ?.lineSequence()
        ?.map(String::trim)
        ?.filter { line -> line.isNotEmpty() && !line.startsWith("#") }
        ?.toList()
        .orEmpty()

    private fun requiredText(path: Path): String {
        assertTrue(path.exists(), "required repository file is missing: $path")
        return path.readText()
    }

    private fun assertTracked(root: Path, relative: String) {
        val process = ProcessBuilder("git", "-C", root.toString(), "ls-files", "--error-unmatch", "--", relative)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        assertEquals(0, process.waitFor(), "required file is not tracked: $relative\n$output")
    }

    private fun sha256(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path).use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private fun repositoryRoot(): Path {
        val candidates = listOf(Path.of("."), Path.of(".."))
            .map(Path::toAbsolutePath)
            .map(Path::normalize)
        return candidates.singleOrNull { candidate ->
            Files.isRegularFile(candidate.resolve("settings.gradle.kts")) &&
                Files.isRegularFile(candidate.resolve("gradle/wrapper/gradle-wrapper.jar"))
        } ?: error("cannot locate repository root from ${Path.of("").toAbsolutePath()}")
    }

    @Suppress("UNCHECKED_CAST")
    private fun Any?.mapValue(): Map<String, Any?> = this as? Map<String, Any?>
        ?: error("expected YAML mapping but was ${this?.javaClass?.name ?: "null"}")

    private fun Map<String, Any?>.mapValue(key: String): Map<String, Any?> = get(key).mapValue()

    @Suppress("UNCHECKED_CAST")
    private fun Any?.listValue(): List<Any?> = this as? List<Any?>
        ?: error("expected YAML sequence but was ${this?.javaClass?.name ?: "null"}")

    private fun Map<String, Any?>.listValue(key: String): List<Any?> = get(key).listValue()

    private fun Map<String, Any?>.stringMap(): Map<String, String> = mapValues { (_, value) -> value.toString() }

    private data class Workflow(
        val source: String,
        val root: Map<String, Any?>,
        val triggers: Map<String, Any?>,
        val concurrency: Map<String, Any?>,
        val job: Map<String, Any?>,
        val steps: List<Map<String, Any?>>,
    ) {
        val commands: List<String> = steps.flatMap { step ->
            (step["run"] as? String)
                ?.lineSequence()
                ?.map(String::trim)
                ?.filter { line -> line.isNotEmpty() && !line.startsWith("#") }
                ?.toList()
                .orEmpty()
        }
    }

    private companion object {
        const val GRADLE_DISTRIBUTION_SHA256 = "20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78"
        const val GRADLE_DISTRIBUTION_URL =
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.13-bin.zip"
        const val GRADLE_WRAPPER_JAR_SHA256 = "e996d452d2645e70c01c11143ca2d3742734a28da2bf61f25c82bdc288c9e637"
        val FORBIDDEN_COMMAND_SNIPPETS = listOf(
            "upload",
            "install",
            "notify",
            "smoke",
            "hardeningrun",
            "adb",
            "publish",
            "gh release",
            "git tag",
        )
    }
}
