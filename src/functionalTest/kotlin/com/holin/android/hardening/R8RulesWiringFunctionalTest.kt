package com.holin.android.hardening

import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.readLines
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.gradle.testkit.runner.GradleRunner
import org.junit.jupiter.api.io.TempDir

class R8RulesWiringFunctionalTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `public variant rules stay ordinary when disabled and replace only app rules when enabled`() {
        writeAndroidFixture()
        val originalRules = projectDirectory.resolve("proguard-rules.pro")
        val originalText = originalRules.readText()
        val generatedRules = projectDirectory.resolve(
            "build/intermediates/hardening/demoRelease/r8/filtered-proguard-rules.pro",
        )
        val decisionReport = projectDirectory.resolve(
            "build/reports/hardening/demoRelease/r8-rules-manifest.json",
        )

        runner("dumpDemoReleaseProguardFiles").build()

        val disabledFiles = dumpedProguardFiles()
        assertTrue(
            disabledFiles.contains(canonical(originalRules)),
            "disabled variant.proguardFiles=$disabledFiles",
        )
        assertFalse(disabledFiles.contains(canonical(generatedRules)))
        assertFalse(generatedRules.exists())
        assertFalse(decisionReport.exists())
        assertTrue(originalRules.readText() == originalText)

        val enabledBuild = runner(
            "-PandroidHardening=true",
            "dumpDemoReleaseProguardFiles",
            "auditHardeningDemoRelease",
        ).build()

        val enabledFiles = dumpedProguardFiles()
        assertFalse(enabledFiles.contains(canonical(originalRules)))
        assertTrue(enabledFiles.contains(canonical(generatedRules)))
        assertTrue(
            enabledFiles.any {
                Path.of(it).fileName.toString().startsWith("proguard-android-optimize.txt")
            },
            "enabled variant.proguardFiles=$enabledFiles",
        )
        val filtered = generatedRules.readText()
        assertFalse(filtered.contains("-keep class androidx.** { *; }"))
        assertFalse(filtered.contains("-keep class com.google.** { *; }"))
        assertFalse(filtered.contains("@kotlin.Metadata class com.example.demo.match.**"))
        assertFalse(filtered.contains("!transient <fields>;"))
        assertFalse(filtered.contains("-keep class **.R$* { *; }"))
        assertFalse(filtered.contains("-keep class **.*Binding { *; }"))
        assertFalse(filtered.contains("extends android.app.Activity"))
        assertFalse(filtered.contains("extends android.view.View"))
        assertContains(filtered, "-keep public class * extends com.chad.library.adapter4.*")
        assertContains(filtered, "-dontwarn androidx.**")
        assertContains(filtered, "-dontwarn com.google.**")
        assertContains(filtered, "-keep class com.google.firebase.** { *; }")
        assertFalse(filtered.contains("-keep class com.example.demo.match.common.bean.** { *; }"))
        assertContains(filtered, "@com.google.gson.annotations.SerializedName <fields>;")
        assertContains(filtered, "implements java.io.Serializable")
        assertContains(filtered, "native <methods>;")
        assertContains(filtered, "@android.webkit.JavascriptInterface <methods>;")
        assertContains(filtered, "@com.wyjson.router.annotation.Param <fields>;")
        assertContains(filtered, "-keep class io.objectbox.** { *; }")
        assertContains(filtered, "-keep class com.example.demo.match.junkcode.** {*;}")
        assertContains(
            filtered,
            "-keep,allowobfuscation,allowshrinking class * extends kotlin.coroutines.jvm.internal.SuspendLambda",
        )
        assertFalse(
            filtered.contains(
                "-keep,allowobfuscation,allowshrinking,allowoptimization class * extends " +
                    "kotlin.coroutines.jvm.internal.SuspendLambda",
            ),
        )
        assertContains(filtered, "-keep class com.chad.library.adapter.** { *; }")
        assertContains(
            filtered,
            "-adaptclassstrings com.example.demo.match.FixtureOwned,com.example.demo.match.FixtureOwned${'$'}*",
        )
        assertContains(filtered, "-keep public class * extends com.example.core.widget.BaseViewHolder")
        assertContains(filtered, "extends com.chad.library.adapter4.viewholder.QuickViewHolder")
        assertContains(filtered, "extends com.chad.library.adapter4.viewholder.DataBindingHolder")
        assertEquals(
            1,
            filtered.lineSequence().count { line ->
                line == "-keep,allowobfuscation public class * extends com.chad.library.adapter4.*"
            },
        )
        val report = decisionReport.readText()
        assertContains(report, "\"variantName\":\"demoRelease\"")
        assertContains(report, "\"sourceFile\":\"proguard-rules.pro\"")
        assertContains(report, "\"sourceWasReplaced\":true")
        assertContains(report, "\"reason\":\"PRESERVED_EXACT_RULE\"")
        assertContains(report, "\"reason\":\"BROAD_ANDROIDX\"")
        assertEquals(
            0,
            "\"reason\":\"BROAD_WILDCARD_SUBCLASS\"".toRegex().findAll(report).count(),
        )
        assertContains(
            report,
            "\"directive\":\"-keep public class * extends com.chad.library.adapter4.*\",\"action\":\"PRESERVE\",\"reason\":\"UNKNOWN_RULE\"",
        )
        assertContains(
            report,
            "\"directive\":\"-keep class com.example.demo.match.common.bean.** { *; }\",\"action\":\"REMOVE\",\"reason\":\"BROAD_OWNED_PACKAGE\"",
        )
        assertContains(enabledBuild.output, "Hardening R8 rule decisions:")
        assertTrue(originalRules.readText() == originalText)
    }

    @Test
    fun `legacy default config flavor dimensions still replace the selected variant rules`() {
        writeAndroidFixture()
        val buildFile = projectDirectory.resolve("build.gradle")
        buildFile.writeText(
            buildFile.readText()
                .replace("flavorDimensions += 'channel'", "")
                .replace("dimension = 'channel'", "")
                .replace(
                    "versionName = '1.0'",
                    "versionName = '1.0'\n                    setFlavorDimensions(['channel'])",
                ),
        )

        runner(
            "-PandroidHardening=true",
            "dumpDemoReleaseProguardFiles",
            "auditHardeningDemoRelease",
        ).build()

        val files = dumpedProguardFiles()
        assertFalse(files.contains(canonical(projectDirectory.resolve("proguard-rules.pro"))))
        assertTrue(
            files.contains(
                canonical(
                    projectDirectory.resolve(
                        "build/intermediates/hardening/demoRelease/r8/filtered-proguard-rules.pro",
                    ),
                ),
            ),
        )
    }

    private fun writeAndroidFixture() {
        val sdk = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
        require(!sdk.isNullOrBlank()) { "ANDROID_HOME or ANDROID_SDK_ROOT is required for the AGP TestKit fixture" }
        check(ProcessBuilder("git", "init", "-q", projectDirectory.toString()).start().waitFor() == 0)
        installPinnedLegacyPluginFixture(projectDirectory)
        val pluginBuild = Path.of(System.getProperty("user.dir"))
            .toAbsolutePath()
            .normalize()
            .toString()
            .replace("\\", "\\\\")
            .replace("'", "\\'")
        projectDirectory.resolve("settings.gradle").writeText(
            """
            pluginManagement {
                includeBuild('$pluginBuild')
                repositories {
                    google()
                    mavenCentral()
                    gradlePluginPortal()
                }
            }
            dependencyResolutionManagement {
                repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
                repositories {
                    google()
                    mavenCentral()
                }
            }
            rootProject.name = 'r8-rules-wiring-fixture'
            """.trimIndent(),
        )
        projectDirectory.resolve("local.properties").writeText("sdk.dir=${sdk.replace("\\", "\\\\")}\n")
        projectDirectory.resolve("src/main").createDirectories()
        projectDirectory.resolve("src/main/AndroidManifest.xml").writeText("<manifest />\n")
        projectDirectory.resolve("src/main/java/com/example/demo/match").createDirectories()
        projectDirectory.resolve("src/main/java/com/example/demo/match/FixtureOwned.java").writeText(
            "package com.example.demo.match; public final class FixtureOwned {}\n",
        )
        projectDirectory.resolve("proguard-rules.pro").writeText(FIXTURE_RULES)
        projectDirectory.resolve("legacy-preserved-rules.pro").writeText(
            "-keep class com.example.demo.match.junkcode.** {*;}\n",
        )
        projectDirectory.resolve("owned-r8-rules.pro").writeText(FIXTURE_ADDITIONAL_RULES)
        projectDirectory.resolve("build.gradle").writeText(
            """
            plugins {
                id 'com.android.application' version '8.13.2'
                id 'org.jetbrains.kotlin.android' version '2.3.0'
                id 'com.holin.android.hardening'
            }

            def androidHardeningRequested = providers.gradleProperty('androidHardening')
                .map { it.toBoolean() }
                .orElse(false)

            android {
                namespace = 'com.example.demo.match'
                compileSdk = 35
                defaultConfig {
                    applicationId = 'com.example.demo.match'
                    minSdk = 26
                    targetSdk = 35
                    versionCode = 1
                    versionName = '1.0'
                }
                signingConfigs {
                    fixture {
                        storeFile = file('unused-fixture.p12')
                        storePassword = 'fixture-password'
                        keyAlias = 'fixture-key'
                        keyPassword = 'fixture-password'
                        storeType = 'PKCS12'
                    }
                }
                flavorDimensions += 'channel'
                productFlavors {
                    demo {
                        dimension = 'channel'
                        signingConfig = signingConfigs.fixture
                    }
                }
                buildTypes {
                    release {
                        minifyEnabled = true
                        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
                    }
                }
            }

            androidHardening {
                enabled.set(providers.gradleProperty('androidHardening').map { it.toBoolean() }.orElse(false))
                projectKey.set('demo')
                variants.include('demoRelease')
                ownership {
                    module(':') { sourceSets.add('main') }
                }
                rules {
                    sourceFiles.from('proguard-rules.pro')
                    preserveExactRules.from('legacy-preserved-rules.pro')
                    additionalRules.from('owned-r8-rules.pro')
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

            gradle.taskGraph.whenReady {
                tasks.matching { it.name.startsWith('auditHardening') }.configureEach {
                    legacyPluginObservations.set(rootProject.file('fixture-legacy-plugin-observations.txt').readLines())
                }
            }

            androidComponents {
                onVariants(selector().withName('demoRelease')) { variant ->
                    def ruleFiles = variant.proguardFiles
                    def dump = layout.buildDirectory.file('proguard-files.txt')
                    tasks.register('dumpDemoReleaseProguardFiles') {
                        outputs.file(dump)
                        outputs.upToDateWhen { false }
                        if (androidHardeningRequested.get()) {
                            dependsOn 'prepareHardeningDemoRelease',
                                'generateHardeningDemoReleaseCodeMapping',
                                'generateHardeningDemoReleaseR8Rules'
                        }
                        doLast {
                            dump.get().asFile.parentFile.mkdirs()
                            dump.get().asFile.text = ruleFiles.get()
                                .collect { it.asFile.absoluteFile.toPath().normalize().toString() }
                                .join('\n')
                        }
                    }
                }
            }
            """.trimIndent(),
        )
    }

    private fun dumpedProguardFiles(): List<String> = projectDirectory.resolve("build/proguard-files.txt")
        .readLines()
        .filter(String::isNotBlank)

    private fun canonical(path: Path): String = path.toFile().canonicalFile.toPath().toString()

    private fun runner(vararg arguments: String): GradleRunner = GradleRunner.create()
        .withProjectDir(projectDirectory.toFile())
        .withTestKitDir(sharedGradleUserHome().toFile())
        .withArguments("--offline", "--stacktrace", *arguments)

    private fun sharedGradleUserHome(): Path = Path.of(
        System.getenv("GRADLE_USER_HOME") ?: "${System.getProperty("user.home")}/.gradle",
    )

    private companion object {
        val FIXTURE_ADDITIONAL_RULES = """
            -keep,allowobfuscation class * implements androidx.viewbinding.ViewBinding
            -keepclassmembers class * implements androidx.viewbinding.ViewBinding {
                public static *** inflate(...);
            }

            -keep,allowobfuscation,allowshrinking,allowoptimization class com.example.core.common.BaseActivity
            -keep,allowobfuscation,allowshrinking,allowoptimization class * extends com.example.core.common.BaseActivity
            -keep,allowobfuscation,allowshrinking,allowoptimization class com.example.core.common.BaseFragment
            -keep,allowobfuscation,allowshrinking,allowoptimization class * extends com.example.core.common.BaseFragment
            -keep,allowobfuscation,allowshrinking,allowoptimization class com.example.core.common.BaseDialogFragment
            -keep,allowobfuscation,allowshrinking,allowoptimization class * extends com.example.core.common.BaseDialogFragment
            -keep,allowobfuscation,allowshrinking,allowoptimization class com.example.core.common.BaseBottomSheetDialogFragment
            -keep,allowobfuscation,allowshrinking,allowoptimization class * extends com.example.core.common.BaseBottomSheetDialogFragment
        """.trimIndent() + "\n"

        val FIXTURE_RULES = """
            -keep class androidx.** { *; }
            -dontwarn androidx.**
            -keep class com.google.** { *; }
            -dontwarn com.google.**
            -keep class com.google.firebase.** { *; }
            -keep @kotlin.Metadata class com.example.demo.match.**
            -keepclassmembers class * {
                !transient <fields>;
            }
            -keep class **.R${'$'}* { *; }
            -keep class **.*Binding { *; }
            -keep public class * extends android.app.Activity
            -keep public class * extends android.view.View { *; }
            -keep class com.chad.library.adapter.** { *; }
            -keep public class * extends com.example.core.widget.BaseViewHolder
            -keep public class * extends com.chad.library.adapter4.*
            -keepclassmembers class **${'$'}** extends com.chad.library.adapter4.viewholder.QuickViewHolder {
                <init>(...);
            }
            -keepclassmembers class **${'$'}** extends com.chad.library.adapter4.viewholder.DataBindingHolder {
                <init>(...);
            }
            -keep,allowobfuscation public class * extends com.chad.library.adapter4.*
            -keep class com.example.demo.match.common.bean.** { *; }
            -keepclassmembers,allowobfuscation class * {
                @com.google.gson.annotations.SerializedName <fields>;
            }
            -keepclassmembers class * implements java.io.Serializable {
                private void writeObject(java.io.ObjectOutputStream);
            }
            -keepclasseswithmembernames class * {
                native <methods>;
            }
            -keepclassmembers class * {
                @android.webkit.JavascriptInterface <methods>;
            }
            -keepclassmembers class * {
                @com.wyjson.router.annotation.Param <fields>;
            }
            -keep class io.objectbox.** { *; }
            -keep class com.example.demo.match.junkcode.** {*;}
        """.trimIndent() + "\n"
    }
}
