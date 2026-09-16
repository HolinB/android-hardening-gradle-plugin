package com.holin.android.hardening

import com.holin.android.hardening.state.PortableBaselineIdentityMigration
import com.holin.android.hardening.state.CanonicalContentDomain
import com.holin.android.hardening.state.PortableStateIdentityMigration
import com.holin.android.hardening.state.PortableStateMigrationDescriptor
import com.holin.android.hardening.state.PortableStateMigrationDescriptorCodec
import com.holin.android.hardening.state.Sha256
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.COPY_ATTRIBUTES
import java.nio.file.StandardOpenOption.APPEND
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.gradle.testkit.runner.GradleRunner
import org.junit.jupiter.api.io.TempDir

class AndroidHardeningPluginFunctionalTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `all seven selected variant tasks are discoverable while disabled`() {
        writeFixture()

        val result = runner("tasks", "--all").build()

        REQUIRED_TASKS.forEach { task -> assertTrue(result.output.contains(task), "missing $task") }
    }

    @Test
    fun `two arbitrary included variants receive the complete portable task family`() {
        writeFixture(variant = "demoQa", additionalVariants = listOf("stagingRelease"))

        val tasks = runner("tasks", "--all").build().output

        listOf("DemoQa", "StagingRelease").forEach { suffix ->
            PORTABLE_TASK_PREFIXES.forEach { prefix ->
                assertTrue(tasks.contains("$prefix$suffix"), "missing $prefix$suffix")
            }
        }
        assertFalse(tasks.contains("demoDebug"))
    }

    @Test
    fun `disabled bundle entry prints only its exact corrected opt in command`() {
        writeFixture()

        val result = runner("hardeningBundleDemoRelease").buildAndFail()

        assertTrue(result.output.contains("./gradlew -PandroidHardening=true hardeningBundleDemoRelease"))
        assertFalse(result.output.contains("./gradlew -PandroidHardening=true hardeningAssembleDemoRelease"))
    }

    @Test
    fun `disabled assemble entry prints only its exact corrected opt in command`() {
        writeFixture()

        val result = runner("hardeningAssembleDemoRelease").buildAndFail()

        assertTrue(result.output.contains("./gradlew -PandroidHardening=true hardeningAssembleDemoRelease"))
        assertFalse(result.output.contains("./gradlew -PandroidHardening=true hardeningBundleDemoRelease"))
    }

    @Test
    fun `each disabled internal lifecycle task fails closed with the bundle opt in command`() {
        writeFixture()

        INTERNAL_TASKS.forEach { task ->
            val result = runner(task).buildAndFail()

            assertTrue(
                result.output.contains("./gradlew -PandroidHardening=true hardeningBundleDemoRelease"),
                "$task did not print the corrected bundle opt-in command",
            )
            assertFalse(result.output.contains("./gradlew -PandroidHardening=true hardeningAssembleDemoRelease"))
        }
    }

    @Test
    fun `normal release dry runs have no hardening task dependency`() {
        writeFixture()

        val assemble = runner("assembleDemoRelease", "--dry-run").build()
        val bundle = runner("bundleDemoRelease", "--dry-run").build()

        assertFalse(assemble.output.contains("HardeningDemoRelease"))
        assertFalse(assemble.output.contains("hardeningAssembleDemoRelease"))
        assertFalse(bundle.output.contains("HardeningDemoRelease"))
        assertFalse(bundle.output.contains("hardeningBundleDemoRelease"))
    }

    @Test
    fun `ordinary task discovery does not validate hardening only legacy state`() {
        writeFixture(configureLegacyBaseline = false, declareLegacyPlugin = false)

        val result = runner("tasks", "--all").build()

        assertTrue(result.output.contains("prepareHardeningDemoRelease"))
    }

    @Test
    fun `ordinary task discovery does not read a missing migration descriptor`() {
        writeFixture(configureMigration = true, migrationDescriptorExists = false)

        val result = runner("tasks", "--all").build()

        assertTrue(result.output.contains("prepareHardeningDemoRelease"))
        assertFalse(projectDirectory.resolve("fixture-state").exists())
    }

    @Test
    fun `enabled hardening requires a configured migration descriptor when automatic migration is enabled`() {
        writeFixture(configureMigration = true, migrationDescriptorExists = false)

        val result = runner("-PandroidHardening=true", "prepareHardeningDemoRelease").buildAndFail()

        assertTrue(result.output.contains("property 'migrationDescriptor'"), result.output)
        assertFalse(projectDirectory.resolve("fixture-state").exists())
    }

    @Test
    fun `explicit prepare migrates matching legacy state without quarantine`() {
        writeFixture()
        runner("-PandroidHardening=true", "prepareHardeningDemoRelease").build()
        val fixture = writeLegacyStateMigrationFixture()
        val pointerBefore = Files.readString(fixture.activePointer)
        val historyBefore = Sha256.canonicalPayload(fixture.stateRoot.resolve("history"))

        runner("-PandroidHardening=true", "prepareHardeningDemoRelease").build()

        val pointer = jsonObject(Files.readString(fixture.activePointer))
        val snapshot = fixture.stateRoot.resolve("current/snapshots").resolve(pointer.getValue("snapshotId") as String)
        val identity = jsonObject(Files.readString(snapshot.resolve("manifest.json"))).getValue("identity") as Map<*, *>
        assertEquals(fixture.targetStateConfiguration, identity["configurationSha256"])
        assertEquals(fixture.generation, (pointer.getValue("generation") as Number).toLong())
        assertFalse(pointerBefore == Files.readString(fixture.activePointer))
        assertEquals(historyBefore, Sha256.canonicalPayload(fixture.stateRoot.resolve("history")))
        assertFalse(Files.exists(fixture.stateRoot.resolve("quarantine")))
        assertEquals(fixture.mappingSha256, Sha256.file(snapshot.resolve("mapping.txt")))
        assertEquals(fixture.registrySha256, Sha256.file(snapshot.resolve("registry.json")))
        assertEquals(fixture.seedSha256, Sha256.file(snapshot.resolve("seed.bin")))
    }

    @Test
    fun `migration descriptor mismatch leaves current state and history untouched without quarantine`() {
        writeFixture()
        runner("-PandroidHardening=true", "prepareHardeningDemoRelease").build()
        val fixture = writeLegacyStateMigrationFixture("9".repeat(64))
        val pointerBefore = Files.readString(fixture.activePointer)
        val historyBefore = Sha256.canonicalPayload(fixture.stateRoot.resolve("history"))

        val result = runner("-PandroidHardening=true", "prepareHardeningDemoRelease").buildAndFail()

        assertTrue(result.output.contains("migration state payload hashes differ from its descriptor"), result.output)
        assertEquals(pointerBefore, Files.readString(fixture.activePointer))
        assertEquals(historyBefore, Sha256.canonicalPayload(fixture.stateRoot.resolve("history")))
        assertFalse(Files.exists(fixture.stateRoot.resolve("quarantine")))
    }

    @Test
    fun `enabled hardening requires a configured legacy baseline`() {
        writeFixture(configureLegacyBaseline = false, declareLegacyPlugin = false)

        val result = runner("-PandroidHardening=true", "prepareHardeningDemoRelease").buildAndFail()

        assertTrue(result.output.contains("legacyPlugins.baselineFile must be configured"), result.output)
    }

    @Test
    fun `enabled hardening requires a legacy declaration when compatibility verification is enabled`() {
        writeFixture(declareLegacyPlugin = false)

        val result = runner("-PandroidHardening=true", "prepareHardeningDemoRelease").buildAndFail()

        assertTrue(result.output.contains("legacyPlugins must declare at least one plugin"), result.output)
    }

    @Test
    fun `enabled hardening resolves legacy declaration inputs`() {
        writeFixture(legacyConfigurationExists = false)

        val result = runner("-PandroidHardening=true", "prepareHardeningDemoRelease").buildAndFail()

        assertTrue(result.output.contains("legacy plugin fixture configuration input is missing"), result.output)
    }

    @Test
    fun `enabled non AGP fixture does not archive when its declared legacy plugin is absent`() {
        writeFixture()

        val result = runner("-PandroidHardening=true", "hardeningBundleDemoRelease").buildAndFail()

        val variantRoot = projectDirectory.resolve("fixture-state/demo/demoRelease")
        assertTrue(result.output.contains("legacy plugin com.example.legacy 1.2.3 is missing"), result.output)
        assertFalse(variantRoot.resolve("current/active.json").exists())
        assertFalse(Files.isDirectory(variantRoot.resolve("history")))
        assertFalse(projectDirectory.resolve(".hardening").exists())
    }

    @Test
    fun `enabled verify task fails closed when its declared legacy plugin is absent`() {
        writeFixture()

        val result = runner("-PandroidHardening=true", "verifyHardeningDemoRelease").buildAndFail()

        assertTrue(result.output.contains("legacy plugin com.example.legacy 1.2.3 is missing"), result.output)
    }

    @Test
    fun `separate enabled invocations retain separate prepared handoffs`() {
        writeFixture()

        runner("-PandroidHardening=true", "prepareHardeningDemoRelease").build()
        runner("-PandroidHardening=true", "prepareHardeningDemoRelease").build()

        val prepared = projectDirectory.resolve("build/hardening/demoRelease")
            .listDirectoryEntries("prepared-*")
        assertEquals(2, prepared.size)
        assertEquals(2, prepared.map { it.fileName.toString() }.distinct().size)
    }

    @Test
    fun `enabled invocation without Android metadata fails closed`() {
        writeFixture(includeAndroid = false)

        val result = runner("-PandroidHardening=true", "prepareHardeningDemoRelease").buildAndFail()

        assertTrue(result.output.contains("requires an Android extension"))
        assertFalse(projectDirectory.resolve("fixture-state").exists())
    }

    @Test
    fun `mapping store parent symlink is rejected from the trusted project boundary`() {
        writeFixture(mappingStore = ".hardening/mappings")
        val outside = projectDirectory.resolve("outside").also(Files::createDirectories)
        Files.createSymbolicLink(projectDirectory.resolve(".hardening"), outside)

        val result = runner("-PandroidHardening=true", "prepareHardeningDemoRelease").buildAndFail()

        assertTrue(result.output.contains("symlink is not allowed in hardening lock path"))
        assertFalse(outside.resolve("mappings/demo/demoRelease/locks/state.lock").exists())
        assertFalse(outside.resolve("mappings/demo/demoRelease/locks/state.lock.owner.json").exists())
    }

    @Test
    fun `demo debug exposes baseline comparison smoke and run without contaminating build task graphs`() {
        writeFixture(variant = "demoDebug")

        val tasks = runner("tasks", "--all").build().output
        val bundle = runner("-PandroidHardening=true", "hardeningBundleDemoDebug", "--dry-run").build().output
        val assemble = runner("-PandroidHardening=true", "hardeningAssembleDemoDebug", "--dry-run").build().output
        val smoke = runner("-PandroidHardening=true", "smokeHardeningDemoDebug", "--dry-run").build().output
        val run = runner("-PandroidHardening=true", "hardeningRunDemoDebug", "--dry-run").build().output

        NEW_DEBUG_TASKS.forEach { task -> assertTrue(tasks.contains(task), "missing $task") }
        listOf(bundle, assemble).forEach { graph ->
            assertFalse(graph.contains("compareHardeningDemoDebug"))
            assertFalse(graph.contains("smokeHardeningDemoDebug"))
            assertFalse(graph.contains("adb", ignoreCase = true))
            assertFalse(graph.contains("showcase", ignoreCase = true))
            assertFalse(graph.contains("upload", ignoreCase = true))
        }
        assertFalse(smoke.contains("compareHardeningDemoDebug"))
        assertFalse(smoke.contains("assembleHardeningDemoDebugUniversalApk"))
        assertTrue(run.indexOf("compareHardeningDemoDebug") < run.indexOf("smokeHardeningDemoDebug"))
        assertTrue(run.indexOf("smokeHardeningDemoDebug") < run.indexOf("archiveHardeningDemoDebug"))
        assertTrue(run.indexOf("archiveHardeningDemoDebug") < run.indexOf("hardeningRunDemoDebug"))
        assertFalse(run.contains("showcase", ignoreCase = true))
        assertFalse(run.contains("upload", ignoreCase = true))
    }

    @Test
    fun `authorized smoke depends on compare and is skipped after compare failure with continue`() {
        writeFixture(variant = "demoDebug")
        val buildDirectory = projectDirectory.resolve("build").also(Files::createDirectories)
        buildDirectory.resolve("fixture.apk").writeText("apk")
        buildDirectory.resolve("fixture-report.json").writeText("not-needed-when-compare-fails")
        Files.writeString(
            projectDirectory.resolve("build.gradle"),
            """

            afterEvaluate {
                tasks.named('smokeHardeningDemoDebug') {
                    serial.set('SERIAL-1')
                    hardenedUniversalApk.set(layout.buildDirectory.file('fixture.apk'))
                    comparisonReport.set(layout.buildDirectory.file('fixture-report.json'))
                    sdkDirectory.set(layout.projectDirectory.dir('fixture-sdk'))
                    doFirst { file('smoke-ran.txt').text = 'ran' }
                }
            }
            """.trimIndent(),
            APPEND,
        )

        val result = runner(
            "-PandroidHardening=true",
            "hardeningRunDemoDebug",
            "--continue",
        ).buildAndFail()

        assertTrue(result.output.contains("> Task :compareHardeningDemoDebug FAILED"), result.output)
        assertFalse(projectDirectory.resolve("smoke-ran.txt").exists())
    }

    private fun writeFixture(
        includeAndroid: Boolean = true,
        mappingStore: String = "fixture-state",
        variant: String = "demoRelease",
        additionalVariants: List<String> = emptyList(),
        configureLegacyBaseline: Boolean = true,
        declareLegacyPlugin: Boolean = true,
        legacyConfigurationExists: Boolean = true,
        configureMigration: Boolean = false,
        migrationDescriptorExists: Boolean = true,
    ) {
        check(ProcessBuilder("git", "init", "-q", projectDirectory.toString()).start().waitFor() == 0)
        projectDirectory.resolve("settings.gradle").writeText("rootProject.name = 'hardening-fixture'\n")
        projectDirectory.resolve("src/main/java/com/example/demo/fixture").createDirectories()
        projectDirectory.resolve("app/src/main/java/com/example/demo/fixture").createDirectories()
        projectDirectory.resolve("src/main/java/com/example/demo/fixture/FixtureOwned.kt").writeText(
            "package com.example.demo.fixture\nclass FixtureOwned\n",
        )
        projectDirectory.resolve("app/src/main/java/com/example/demo/fixture/FixtureOwned.kt").writeText(
            "package com.example.demo.fixture\nclass FixtureOwned\n",
        )
        if (configureLegacyBaseline) {
            projectDirectory.resolve("legacy").createDirectories()
            projectDirectory.resolve("legacy/baseline.json").writeText("{}\n")
        }
        if (declareLegacyPlugin && legacyConfigurationExists) {
            projectDirectory.resolve("legacy").createDirectories()
            projectDirectory.resolve("legacy/config.gradle").writeText("// fixture\n")
        }
        if (configureMigration && migrationDescriptorExists) {
            projectDirectory.resolve("hardening").createDirectories()
        }
        val androidFixture = if (includeAndroid) {
            """
            class FixtureFlavor {
                String name
                String namespace
                String applicationId
                Integer versionCode
                String versionName
            }
            class FixtureAndroid {
                String namespace
                List<FixtureFlavor> productFlavors
            }
            extensions.add('android', new FixtureAndroid(
                namespace: null,
                productFlavors: [new FixtureFlavor(
                    name: 'demo',
                    namespace: 'com.example.demo.fixture',
                    applicationId: 'com.example.demo.fixture.app',
                    versionCode: 42,
                    versionName: '1.0.0',
                )],
            ))
            """.trimIndent()
        } else {
            ""
        }
        val legacyFixture = if (configureLegacyBaseline) {
            """
                legacyPlugins {
                    baselineFile.set(layout.projectDirectory.file('legacy/baseline.json'))
                    ${if (declareLegacyPlugin) """
                    plugin('fixture') {
                        pluginId.set('com.example.legacy')
                        expectedVersion.set('1.2.3')
                        configurationInputs.from(layout.projectDirectory.file('legacy/config.gradle'))
                        mappingPaths.from(layout.projectDirectory.file('legacy/missing-mapping.txt'))
                    }
                    """.trimIndent() else ""}
                }
            """.trimIndent()
        } else {
            ""
        }
        projectDirectory.resolve("build.gradle").writeText(
            """
            plugins {
                id 'com.holin.android.hardening'
            }

            $androidFixture

            androidHardening {
                enabled.set(providers.gradleProperty('androidHardening').map { it.toBoolean() }.orElse(false))
                projectKey.set('demo')
                variants.include('$variant')
                ${additionalVariants.joinToString("\n                ") { "variants.include('$it')" }}
                ownership {
                    module(':') { sourceSets.add('main') }
                }
                benchmark.mode.set(REPORT_ONLY)
                mapping {
                    storeDirectory.set(layout.projectDirectory.dir('$mappingStore'))
                }
                $legacyFixture
                ${if (configureMigration) """
                compatibility {
                    autoMigrateLegacyState.set(true)
                    migrationDescriptor.set(layout.projectDirectory.file('hardening/portable-state-migration.json'))
                }
                """.trimIndent() else ""}
            }

            tasks.register('assembleDemoRelease')
            tasks.register('bundleDemoRelease')
            """.trimIndent(),
        )
    }

    private fun writeLegacyStateMigrationFixture(
        mappingSha256Override: String? = null,
    ): LegacyStateMigrationFixture {
        val stateRoot = projectDirectory.resolve("fixture-state/demo/demoRelease")
        val sourceConfiguration = "1".repeat(64)
        val prepared = Files.list(projectDirectory.resolve("build/hardening/demoRelease")).use { paths ->
            paths.filter { Files.isDirectory(it) && it.fileName.toString().startsWith("prepared-") }
                .findFirst()
                .orElseThrow { IllegalStateException("fixture prepare output is missing") }
        }
        val manifest = jsonObject(Files.readString(prepared.resolve("manifest.json"))).toMutableMap()
        val identity = (manifest.getValue("identity") as Map<*, *>).entries
            .associateTo(linkedMapOf<String, Any?>()) { (key, value) -> key as String to value }
        val targetConfiguration = identity.getValue("configurationSha256") as String
        identity["configurationSha256"] = sourceConfiguration
        manifest["identity"] = identity
        val generation = (identity.getValue("generation") as Number).toLong()
        val snapshots = stateRoot.resolve("current/snapshots").createDirectories()
        val staging = snapshots.resolve("fixture-staging").createDirectories()
        listOf("mapping.txt", "registry.json", "seed.bin").forEach { name ->
            Files.copy(prepared.resolve(name), staging.resolve(name), COPY_ATTRIBUTES)
        }
        staging.resolve("manifest.json").writeText(JsonOutput.toJson(manifest) + "\n")
        val activePayloadSha256 = Sha256.canonicalPayload(staging, CanonicalContentDomain.LEGACY_V1)
        val snapshotId = "$generation-$activePayloadSha256"
        val snapshot = snapshots.resolve(snapshotId)
        Files.move(staging, snapshot)
        val activePointer = stateRoot.resolve("current/active.json")
        activePointer.writeText(
            "{\"schemaVersion\":1,\"generation\":$generation," +
                "\"snapshotId\":\"$snapshotId\",\"payloadSha256\":\"$activePayloadSha256\"}\n",
        )
        stateRoot.resolve("history/42-${"3".repeat(64)}").createDirectories()
            .resolve("legacy-marker.txt").writeText("immutable history fixture\n")
        val mappingSha256 = Sha256.file(snapshot.resolve("mapping.txt"))
        val registrySha256 = Sha256.file(snapshot.resolve("registry.json"))
        val seedSha256 = Sha256.file(snapshot.resolve("seed.bin"))
        val descriptor = PortableStateMigrationDescriptor(
            2,
            "demo",
            "demoRelease",
            PortableStateIdentityMigration(
                "com.example.demo.fixture",
                "com.example.demo.fixture.app",
                CanonicalContentDomain.LEGACY_V1.id,
                CanonicalContentDomain.HOLIN_1_3.id,
                sourceConfiguration,
                targetConfiguration,
                identity.getValue("lineageId") as String,
                generation,
                activePayloadSha256,
                mappingSha256Override ?: mappingSha256,
                registrySha256,
                seedSha256,
            ),
            PortableBaselineIdentityMigration(
                "owned-artifact-similarity-v1",
                "4".repeat(64),
                "5".repeat(64),
                "6".repeat(64),
                "7".repeat(64),
            ),
        )
        val descriptorPath = projectDirectory.resolve("hardening/portable-state-migration.json")
        descriptorPath.parent.createDirectories()
        descriptorPath.writeText(PortableStateMigrationDescriptorCodec.encode(descriptor))
        Files.writeString(
            projectDirectory.resolve("build.gradle"),
            """

            androidHardening {
                compatibility {
                    autoMigrateLegacyState.set(true)
                    migrationDescriptor.set(layout.projectDirectory.file('hardening/portable-state-migration.json'))
                }
            }
            """.trimIndent(),
            APPEND,
        )
        return LegacyStateMigrationFixture(
            stateRoot,
            stateRoot.resolve("current/active.json"),
            targetConfiguration,
            generation,
            mappingSha256,
            registrySha256,
            seedSha256,
        )
    }

    private fun jsonObject(text: String): Map<String, Any?> =
        (JsonSlurper().parseText(text) as Map<*, *>).entries
            .associate { (key, value) -> key as String to value }

    private fun runner(vararg arguments: String): GradleRunner = GradleRunner.create()
        .withProjectDir(projectDirectory.toFile())
        .withArguments("--stacktrace", *arguments)
        .withPluginClasspath()

    private data class LegacyStateMigrationFixture(
        val stateRoot: Path,
        val activePointer: Path,
        val targetStateConfiguration: String,
        val generation: Long,
        val mappingSha256: String,
        val registrySha256: String,
        val seedSha256: String,
    )

    private companion object {
        val REQUIRED_TASKS = listOf(
            "prepareHardeningDemoRelease",
            "auditHardeningDemoRelease",
            "verifyHardeningDemoRelease",
            "archiveHardeningDemoRelease",
            "hardeningBundleDemoRelease",
            "hardeningAssembleDemoRelease",
            "benchmarkHardeningDemoRelease",
        )
        val INTERNAL_TASKS = listOf(
            "prepareHardeningDemoRelease",
            "auditHardeningDemoRelease",
            "verifyHardeningDemoRelease",
            "archiveHardeningDemoRelease",
            "benchmarkHardeningDemoRelease",
        )
        val NEW_DEBUG_TASKS = listOf(
            "captureHardeningBaselineDemoDebug",
            "compareHardeningDemoDebug",
            "smokeHardeningDemoDebug",
            "hardeningRunDemoDebug",
        )
        val PORTABLE_TASK_PREFIXES = listOf(
            "prepareHardening",
            "auditHardening",
            "verifyHardening",
            "archiveHardening",
            "hardeningBundle",
            "hardeningAssemble",
            "benchmarkHardening",
            "captureHardeningBaseline",
            "compareHardening",
            "compareExternalHardening",
            "smokeHardening",
            "hardeningRun",
        )
    }
}
