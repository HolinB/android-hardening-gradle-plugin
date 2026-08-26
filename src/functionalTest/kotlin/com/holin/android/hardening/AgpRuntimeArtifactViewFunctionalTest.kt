package com.holin.android.hardening

import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFalse
import org.gradle.testkit.runner.GradleRunner
import org.junit.jupiter.api.io.TempDir

class AgpRuntimeArtifactViewFunctionalTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `audit selects one classes jar from an Android project dependency`() {
        writeFixture()

        runner("-PandroidHardening=true", "auditHardeningDemoRelease").build()

        val report = projectDirectory.resolve("build/reports/hardening/demoRelease/audit.json").readText()
        assertContains(report, "\"status\":\"PASS\"")
        assertContains(report, "\"component\":\"project :selector\"")
        assertContains(report, "\"fileName\":\"full.jar\"")
        assertContains(report, "\"component\":\"third.jar\"")
        assertContains(report, "\"webpDiversificationFiles\":[\"src/owned-res/drawable/included.webp\"]")
        assertFalse(report.contains("selector/src/owned-res/drawable/not_included.webp"))
    }

    private fun writeFixture() {
        val sdk = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
        require(!sdk.isNullOrBlank()) { "ANDROID_HOME or ANDROID_SDK_ROOT is required for the AGP TestKit fixture" }
        check(ProcessBuilder("git", "init", "-q", projectDirectory.toString()).start().waitFor() == 0)
        installPinnedLegacyPluginFixture(projectDirectory)
        createFixtureKeyStore()
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
            rootProject.name = 'agp-runtime-artifact-view-fixture'
            include ':selector'
            """.trimIndent(),
        )
        projectDirectory.resolve("local.properties").writeText("sdk.dir=${sdk.replace("\\", "\\\\")}\n")
        projectDirectory.resolve("src/main/java/com/example").createDirectories()
        projectDirectory.resolve("src/main/java/com/example/AppEntry.java").writeText(
            "package com.example; public final class AppEntry {}\n",
        )
        projectDirectory.resolve("src/owned-manifest").createDirectories()
        projectDirectory.resolve("src/owned-manifest/AndroidManifest.xml").writeText("<manifest />\n")
        projectDirectory.resolve("src/owned-res/drawable").createDirectories()
        projectDirectory.resolve("src/owned-res/drawable/included.webp").writeText("fixture-webp")
        projectDirectory.resolve("proguard-rules.pro").writeText("")
        val externalJar = projectDirectory.resolve("libs/third.jar")
        externalJar.parent.createDirectories()
        JarOutputStream(externalJar.toFile().outputStream()).use { jar ->
            jar.putNextEntry(JarEntry("third/marker.txt"))
            jar.write("external".toByteArray())
            jar.closeEntry()
        }
        projectDirectory.resolve("build.gradle").writeText(
            """
            plugins {
                id 'com.android.application' version '8.13.2'
                id 'org.jetbrains.kotlin.android' version '2.3.0'
                id 'com.holin.android.hardening'
            }

            android {
                namespace = 'com.example'
                compileSdk = 35
                defaultConfig {
                    applicationId = 'com.example.app'
                    minSdk = 26
                    targetSdk = 35
                    versionCode = 1
                    proguardFiles 'proguard-rules.pro'
                }
                signingConfigs {
                    fixture {
                        storeFile = file('fixture-signing.p12')
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
                        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
                    }
                }
                sourceSets {
                    main.res.srcDir 'src/owned-res'
                    main.manifest.srcFile 'src/owned-manifest/AndroidManifest.xml'
                }
            }

            dependencies {
                implementation project(':selector')
                implementation files('libs/third.jar')
            }

            androidHardening {
                enabled.set(providers.gradleProperty('androidHardening').map { it.toBoolean() }.orElse(false))
                projectKey.set('demo')
                variants.include('demoRelease')
                ownership {
                    module(':') {
                        sourceSets.add('main')
                        manifestFiles.from('src/owned-manifest/AndroidManifest.xml')
                        webp { include('src/owned-res/drawable/**/*.webp') }
                    }
                    module(':selector') { sourceSets.add('main') }
                }
                rules {
                    sourceFiles.from('proguard-rules.pro')
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
            """.trimIndent(),
        )
        projectDirectory.resolve("selector/src/main/java/com/example/selector").createDirectories()
        projectDirectory.resolve("selector/src/main/java/com/example/selector/Selector.java").writeText(
            "package com.example.selector; public final class Selector {}\n",
        )
        projectDirectory.resolve("selector/src/main/AndroidManifest.xml").writeText("<manifest />\n")
        projectDirectory.resolve("selector/src/owned-res/drawable").createDirectories()
        projectDirectory.resolve("selector/src/owned-res/drawable/not_included.webp").writeText("fixture-webp")
        projectDirectory.resolve("selector/build.gradle").writeText(
            """
            plugins {
                id 'com.android.library'
            }

            android {
                namespace = 'com.example.selector'
                compileSdk = 35
                defaultConfig { minSdk = 26 }
                flavorDimensions += 'channel'
                productFlavors {
                    demo { dimension = 'channel' }
                }
                sourceSets {
                    main.res.srcDir 'src/owned-res'
                }
            }
            """.trimIndent(),
        )
    }

    private fun createFixtureKeyStore() {
        val keyStore = projectDirectory.resolve("fixture-signing.p12")
        val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool")
        val process = ProcessBuilder(
            keytool.toString(),
            "-genkeypair",
            "-alias",
            "fixture-key",
            "-keystore",
            keyStore.toString(),
            "-storetype",
            "PKCS12",
            "-storepass",
            "fixture-password",
            "-keypass",
            "fixture-password",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "3650",
            "-dname",
            "CN=Hardening TestKit Fixture",
            "-noprompt",
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { "fixture keytool failed: $output" }
    }

    private fun runner(vararg arguments: String): GradleRunner = GradleRunner.create()
        .withProjectDir(projectDirectory.toFile())
        .withTestKitDir(sharedGradleUserHome().toFile())
        .withArguments("--offline", "--stacktrace", *arguments)

    private fun sharedGradleUserHome(): Path = Path.of(
        System.getenv("GRADLE_USER_HOME")
            ?: "${System.getProperty("user.home")}/.gradle",
    )
}
