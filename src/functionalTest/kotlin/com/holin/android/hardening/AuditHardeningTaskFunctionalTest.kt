package com.holin.android.hardening

import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFalse
import kotlin.test.assertNull
import org.gradle.testkit.runner.GradleRunner
import org.junit.jupiter.api.io.TempDir

class AuditHardeningTaskFunctionalTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `audit rejects custom Gson field naming before archive or install`() {
        writeFixture(
            "fun gson() = GsonBuilder().setFieldNamingStrategy(ServerNamingStrategy()).create()",
        )

        val failed = runner("-PandroidHardening=true", "auditHardeningDemoRelease").buildAndFail()

        val report = projectDirectory.resolve("build/reports/hardening/demoRelease/audit.json")
        assertContains(failed.output, "src/main/java/com/example/Contract.kt:2: unresolved Gson field naming")
        assertContains(report.readText(), "\"status\":\"FAIL\"")
        assertContains(report.readText(), ".setFieldNamingStrategy(ServerNamingStrategy())")
        assertNull(failed.task(":archiveHardeningDemoRelease"))
        assertNull(failed.task(":smokeHardeningDemoRelease"))
        assertFalse(projectDirectory.resolve("fixture-state/demo/demoRelease/history").toFile().exists())
    }

    @Test
    fun `audit writes FAIL before rejecting dynamic reflection and PASS for a static constant`() {
        writeFixture("fun load(remote: String) = Class.forName(remote)")

        val failed = runner("-PandroidHardening=true", "auditHardeningDemoRelease").buildAndFail()

        val report = projectDirectory.resolve("build/reports/hardening/demoRelease/audit.json")
        assertContains(failed.output, "unresolved app reflection")
        assertContains(report.readText(), "\"status\":\"FAIL\"")
        assertContains(report.readText(), "Class.forName(remote)")
        assertFalse(projectDirectory.resolve("fixture-state/demo/demoRelease/history").toFile().exists())

        val source = projectDirectory.resolve("src/main/java/com/example/Contract.kt")
        source.writeText("package com.example\nprivate const val TYPE = \"com.example.Model\"\nfun load() = Class.forName(TYPE)\n")

        runner("-PandroidHardening=true", "auditHardeningDemoRelease").build()

        assertContains(report.readText(), "\"status\":\"PASS\"")
        assertContains(report.readText(), "\"resolvedName\":\"com.example.Model\"")
    }

    @Test
    fun `hardcoded reference fail policy controls scoped unresolved class member and resource contracts`() {
        writeFixture(
            """
            fun load(remote: String, types: Array<Class<*>>, resources: android.content.res.Resources) {
                Class.forName(remote)
                Model::class.java.getMethod("render", *types)
                resources.getIdentifier(remote, "drawable", "com.example")
            }
            """.trimIndent(),
        )
        val build = projectDirectory.resolve("build.gradle")
        val original = build.readText()
        build.writeText(
            original.replace(
                "module(':') { sourceSets.add('main') }",
                """
                module(':') { sourceSets.add('main') }
                hardcodedReferences {
                    kinds.set([CLASS_NAME, MEMBER_NAME, RESOURCE_NAME])
                    includeGlobs.set(['**/*.kt'])
                    excludeGlobs.set([])
                    failOnUnresolvedOwnedReference.set(false)
                }
                """.trimIndent(),
            ).replace(
                "fullAuditEnabled.set(true)",
                """
                fullAuditEnabled.set(true)
                    unresolvedAppReflectionPolicy.set('REPORT_ONLY')
                    unresolvedResourceLookupPolicy.set('REPORT_ONLY')
                """.trimIndent(),
            ),
        )

        runner("-PandroidHardening=true", "auditHardeningDemoRelease").build()

        val report = projectDirectory.resolve("build/reports/hardening/demoRelease/audit.json")
        assertContains(report.readText(), "\"unresolvedHardcodedReferences\"")
        build.writeText(build.readText().replace("failOnUnresolvedOwnedReference.set(false)", "failOnUnresolvedOwnedReference.set(true)"))

        val failed = runner("-PandroidHardening=true", "auditHardeningDemoRelease").buildAndFail()

        assertContains(failed.output, "unresolved hardcoded reference")
    }

    private fun writeFixture(source: String) {
        check(ProcessBuilder("git", "init", "-q", projectDirectory.toString()).start().waitFor() == 0)
        projectDirectory.resolve("settings.gradle").writeText("rootProject.name = 'audit-fixture'\n")
        projectDirectory.resolve("r8-rules-manifest.json").writeText("{\"schemaVersion\":1}\n")
        projectDirectory.resolve("src/main/java/com/example").createDirectories()
        projectDirectory.resolve("src/main/java/com/example/Contract.kt").writeText("package com.example\n$source\n")
        installPinnedLegacyPluginFixture(projectDirectory)
        projectDirectory.resolve("build.gradle").writeText(
            """
            plugins {
                id 'com.holin.android.hardening'
            }

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
                    namespace: 'com.example',
                    applicationId: 'com.example.app',
                    versionCode: 1,
                    versionName: '1.0.0',
                )],
            ))

            androidHardening {
                enabled.set(providers.gradleProperty('androidHardening').map { it.toBoolean() }.orElse(false))
                projectKey.set('demo')
                variants.include('demoRelease')
                ownership {
                    module(':') { sourceSets.add('main') }
                }
                legacyPlugins {
                    baselineFile.set(rootProject.layout.projectDirectory.file('app/hardening/legacy-plugins-baseline.json'))
                    plugin('androidJunkCode') {
                        pluginId.set('io.github.qq549631030.android-junk-code')
                        expectedVersion.set('1.3.4')
                        configurationInputs.from(rootProject.file('app/build.gradle.kts'), rootProject.file('build.gradle.kts'))
                    }
                    plugin('stringFog') {
                        pluginId.set('stringfog')
                        expectedVersion.set('5.2.0')
                        configurationInputs.from(rootProject.file('app/build.gradle.kts'), rootProject.file('gradle/libs.versions.toml'))
                    }
                    plugin('xmlClassGuard') {
                        pluginId.set('xml-class-guard')
                        expectedVersion.set('1.2.6')
                        configurationInputs.from(rootProject.file('app/build.gradle.kts'), rootProject.file('gradle/libs.versions.toml'))
                        mappingPaths.from(rootProject.file('app/xml-class-mapping.txt'))
                    }
                }
                mapping.storeDirectory.set(layout.projectDirectory.dir('fixture-state'))
            }

            afterEvaluate {
                tasks.named('auditHardeningDemoRelease') {
                    fullAuditEnabled.set(true)
                    appDirectory.set(layout.projectDirectory)
                    r8RulesManifest.set(layout.projectDirectory.file('r8-rules-manifest.json'))
                    legacyPluginsBaseline.set(rootProject.layout.projectDirectory.file('app/hardening/legacy-plugins-baseline.json'))
                    legacyPluginConfigurationInputs.from(
                        rootProject.layout.projectDirectory.file('app/build.gradle.kts'),
                        rootProject.layout.projectDirectory.file('build.gradle.kts'),
                        rootProject.layout.projectDirectory.file('gradle/libs.versions.toml'),
                    )
                    legacyPluginObservations.set(rootProject.file('fixture-legacy-plugin-observations.txt').readLines())
                }
            }
            """.trimIndent(),
        )
    }

    private fun runner(vararg arguments: String): GradleRunner = GradleRunner.create()
        .withProjectDir(projectDirectory.toFile())
        .withArguments("--stacktrace", *arguments)
        .withPluginClasspath()
}
