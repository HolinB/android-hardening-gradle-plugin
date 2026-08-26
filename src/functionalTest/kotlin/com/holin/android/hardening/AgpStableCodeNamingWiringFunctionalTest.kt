package com.holin.android.hardening

import groovy.json.JsonSlurper
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.io.path.createDirectories
import kotlin.io.path.isDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.jupiter.api.io.TempDir

class AgpStableCodeNamingWiringFunctionalTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `debug code mapping uses public scoped and project artifact inputs`() {
        writeFiveModuleDebugFixture()

        val disabled = runner("generateHardeningDemoDebugCodeMapping").buildAndFail()
        assertTrue(disabled.output.contains("Task 'generateHardeningDemoDebugCodeMapping' not found"))

        val result = runner(
            "-PandroidHardening=true",
            "generateHardeningDemoDebugCodeMapping",
        ).build()

        assertEquals(
            TaskOutcome.SUCCESS,
            result.task(":app:generateHardeningDemoDebugCodeMapping")?.outcome,
        )
        val manifest = projectDirectory.resolve(
            "app/build/reports/hardening/demoDebug/code-naming.json",
        ).readText()
        assertContains(manifest, "\"ownedModules\":[\":app\",\":compress\",\":core\",\":selector\",\":ucrop\"]")
        assertContains(manifest, "\"owner\":\"com/example/core/")
        assertFalse(manifest.contains("\"owner\":\"third/"))
        assertContains(
            manifest,
            "\"name\":\"handle\",\"descriptor\":\"(Landroid/view/View;)V\",\"reason\":\"ACTIVITY_VIEW_CALLBACK_KEEP_RULE\"",
        )
        val potentialBeanManifestPath = projectDirectory.resolve(
            "app/build/reports/hardening/demoDebug/potential-bean-fields.json",
        )
        val potentialBeanManifest = requireNotNull(
            JsonSlurper().parseText(potentialBeanManifestPath.readText()) as? Map<*, *>,
        )
        assertEquals(1, (potentialBeanManifest["policyVersion"] as Number).toInt())
        assertEquals(
            listOf(":app", ":compress", ":core", ":selector", ":ucrop"),
            potentialBeanManifest["ownedModules"],
        )
        val protectedFields = requireNotNull(potentialBeanManifest["fields"] as? List<*>)
            .map { raw -> requireNotNull(raw as? Map<*, *>) }
        assertEquals(
            mapOf(":app" to 1, ":core" to 1, ":compress" to 1, ":selector" to 1, ":ucrop" to 1),
            protectedFields.groupingBy { field -> field["modulePath"] as String }.eachCount(),
        )
        assertTrue(protectedFields.all { field -> field["name"] == "beanValue" })
        assertTrue(protectedFields.none { field -> (field["owner"] as String).startsWith("com/vendor/excluded/") })
        assertTrue(protectedFields.none { field -> (field["owner"] as String).startsWith("third/") })
        assertContains(manifest, "\"reason\":\"POTENTIAL_BEAN_INSTANCE_FIELD\"")
        val namingManifest = requireNotNull(JsonSlurper().parseText(manifest) as? Map<*, *>)
        val expectedSymbols = requireNotNull(namingManifest["expectedSymbols"] as? List<*>)
            .map { raw -> requireNotNull(raw as? Map<*, *>) }
        assertTrue(expectedSymbols.none { symbol -> (symbol["owner"] as String).startsWith("com/vendor/excluded/") })
        assertTrue(expectedSymbols.none { symbol ->
            symbol["kind"] == "CLASS" && symbol["owner"] == "com/example/core/BaseActivity"
        })
        assertTrue(expectedSymbols.any { symbol ->
            symbol["kind"] == "METHOD" && symbol["owner"] == "com/example/core/BaseActivity" &&
                symbol["name"] == "ordinary" && symbol["outputOwner"] == "com/example/core/BaseActivity"
        })
        val exclusions = requireNotNull(namingManifest["exclusions"] as? List<*>)
            .map { raw -> requireNotNull(raw as? Map<*, *>) }
        assertTrue(exclusions.any { exclusion ->
            exclusion["kind"] == "CLASS" && exclusion["owner"] == "com/example/core/BaseActivity" &&
                exclusion["reason"] == "R8_HIERARCHY_KEEP_RULE" &&
                (exclusion["evidence"] as String).contains(
                    "-keep public class * extends external.ExternalActivity",
                )
        })
        val applyMappingRules = projectDirectory.resolve(
            "app/build/intermediates/hardening/demoDebug/code-naming/applymapping.pro",
        ).readText()
        listOf(
            "app" to "AppEntry",
            "core" to "Core",
            "compress" to "Compress",
            "selector" to "Selector",
            "ucrop" to "Ucrop",
        ).forEach { (module, owner) ->
            assertContains(
                applyMappingRules,
                "-keep,allowoptimization,allowobfuscation class com.example.$module.$owner\n",
            )
            assertContains(
                applyMappingRules,
                "-keepclassmembers class com.example.$module.$owner {\n    java.lang.String beanValue;\n}",
            )
        }
        assertFalse(applyMappingRules.contains("staticBeanValue"))
        assertFalse(applyMappingRules.contains("transientBeanValue"))
        assertContains(
            applyMappingRules,
            "-keeppackagenames external.program.ExternalProgram\n",
        )
        val filteredRules = projectDirectory.resolve(
            "app/build/intermediates/hardening/demoDebug/r8/filtered-proguard-rules.pro",
        ).readText()
        assertContains(filteredRules, "-keep public class * extends external.ExternalActivity")
    }

    @Test
    fun `DSL declared resource layer contributes custom View exclusion and task input`() {
        writeFiveModuleDebugFixture()

        val result = runner(
            "-PandroidHardening=true",
            "generateHardeningDemoDebugCodeMapping",
        ).build()

        val manifest = projectDirectory.resolve(
            "app/build/reports/hardening/demoDebug/code-naming.json",
        ).readText()
        assertContains(manifest, "\"owner\":\"com/example/app/DslResourceView\"")
        assertContains(manifest, "\"reason\":\"LAYOUT_CUSTOM_VIEW\"")
        assertTrue(
            result.output.contains("hardening static resource input includes app/src/main/res-extra"),
            result.output,
        )
    }

    @Test
    fun `resource input probe is up to date until the DSL layout changes`() {
        writeFiveModuleDebugFixture()

        val first = runner(
            "-PandroidHardening=true",
            "generateHardeningDemoDebugCodeMapping",
            "probeStaticResourceInputs",
        ).build()
        val second = runner(
            "-PandroidHardening=true",
            "generateHardeningDemoDebugCodeMapping",
            "probeStaticResourceInputs",
        ).build()
        projectDirectory.resolve("app/src/main/res-extra/layout/dsl_custom.xml").writeText(
            "<com.example.app.DslResourceView xmlns:android=\"http://schemas.android.com/apk/res/android\" android:layout_width=\"wrap_content\" android:layout_height=\"match_parent\" />\n",
        )
        val third = runner(
            "-PandroidHardening=true",
            "generateHardeningDemoDebugCodeMapping",
            "probeStaticResourceInputs",
        ).build()

        assertEquals(TaskOutcome.SUCCESS, first.task(":app:probeStaticResourceInputs")?.outcome)
        assertEquals(TaskOutcome.UP_TO_DATE, second.task(":app:probeStaticResourceInputs")?.outcome)
        assertEquals(TaskOutcome.SUCCESS, third.task(":app:probeStaticResourceInputs")?.outcome)
    }

    @Test
    fun `release audit receives explicitly owned main resources`() {
        writeFiveModuleDebugFixture()

        val result = runner(
            "-PandroidHardening=true",
            "auditHardeningDemoRelease",
        ).build()

        assertEquals(TaskOutcome.SUCCESS, result.task(":app:auditHardeningDemoRelease")?.outcome)
        val report = projectDirectory.resolve(
            "app/build/reports/hardening/demoRelease/audit.json",
        ).readText()
        assertContains(report, "app/src/main/res/layout/release_conventional.xml")
        assertContains(report, "\"kind\":\"LAYOUT_CUSTOM_VIEW\"")
        assertContains(report, "\"symbol\":\"com.example.app.DslResourceView\"")
    }

    @Test
    fun `explicitly empty debug resource layers do not fall back to conventional resources`() {
        writeFiveModuleDebugFixture(explicitEmptyDebugResourceLayers = true)

        val result = runner(
            "-PandroidHardening=true",
            "auditHardeningDemoDebug",
        ).build()

        assertEquals(TaskOutcome.SUCCESS, result.task(":app:auditHardeningDemoDebug")?.outcome)
        val report = projectDirectory.resolve(
            "app/build/reports/hardening/demoDebug/audit.json",
        ).readText()
        assertFalse(report.contains("app/src/main/res/layout/release_conventional.xml"))
        assertFalse(report.contains("\"symbol\":\"com.example.app.DslResourceView\""))
    }

    @Test
    fun `debug schema reset quarantines debug and never opens release state`() {
        writeFiveModuleDebugFixture()
        seedOldDebugAndReleaseStates()
        val debugStateRoot = stateRoot("demoDebug")
        val releaseStateRoot = stateRoot("demoRelease")
        val releaseHash = canonicalTreeHash(releaseStateRoot)

        runner("-PandroidHardening=true", "prepareHardeningDemoDebug").build()

        assertTrue(debugStateRoot.resolve("quarantine").isDirectory())
        assertEquals(releaseHash, canonicalTreeHash(releaseStateRoot))
    }

    private fun writeFiveModuleDebugFixture(explicitEmptyDebugResourceLayers: Boolean = false) {
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
                    maven {
                        url = uri('repo')
                        metadataSources { gradleMetadata() }
                    }
                    google()
                    mavenCentral()
                }
            }
            rootProject.name = 'agp-stable-code-naming-fixture'
            include ':app', ':core', ':compress', ':selector', ':ucrop'
            """.trimIndent(),
        )
        projectDirectory.resolve("local.properties").writeText("sdk.dir=${sdk.replace("\\", "\\\\")}\n")
        projectDirectory.resolve("build.gradle").writeText(
            """
            plugins {
                id 'com.android.application' version '8.13.2' apply false
                id 'org.jetbrains.kotlin.android' version '2.3.0' apply false
                id 'com.android.library' version '8.13.2' apply false
            }
            """.trimIndent(),
        )
        writeExternalJar()
        writeExternalAndroidAar(sdk)
        writeExternalProgramModule()
        writeAppBuild(explicitEmptyDebugResourceLayers)
        LIBRARY_MODULES.forEach(::writeLibraryBuild)
    }

    private fun writeAppBuild(explicitEmptyDebugResourceLayers: Boolean) {
        val app = projectDirectory.resolve("app")
        app.resolve("src/main/java/com/example/app").createDirectories()
        app.resolve("src/main/java/com/example/app/AppEntry.java").writeText(
            """
            package com.example.app;
            public final class AppEntry {
                public String beanValue;
                public static String staticBeanValue;
                public transient String transientBeanValue;
                public external.program.ExternalProgram reflect(
                    external.program.ExternalProgram value
                ) { return value; }
            }
            """.trimIndent() + "\n",
        )
        app.resolve("src/main/java/com/example/app/DslResourceView.java").writeText(
            "package com.example.app; public final class DslResourceView extends android.view.View { public DslResourceView(android.content.Context context) { super(context); } }\n",
        )
        app.resolve("src/main/java/com/vendor/excluded").createDirectories()
        app.resolve("src/main/java/com/vendor/excluded/ExcludedBean.java").writeText(
            "package com.vendor.excluded; public final class ExcludedBean { public String beanValue; }\n",
        )
        app.resolve("src/main/AndroidManifest.xml").writeText("<manifest />\n")
        app.resolve("proguard-rules.pro").writeText(
            "-keep public class * extends external.ExternalActivity\n",
        )
        app.resolve("src/main/res/layout").createDirectories()
        app.resolve("src/main/res/layout/release_conventional.xml").writeText(
            "<com.example.app.DslResourceView xmlns:android=\"http://schemas.android.com/apk/res/android\" android:layout_width=\"match_parent\" android:layout_height=\"match_parent\" />\n",
        )
        app.resolve("src/main/res-extra/layout").createDirectories()
        app.resolve("src/main/res-extra/layout/dsl_custom.xml").writeText(
            "<com.example.app.DslResourceView xmlns:android=\"http://schemas.android.com/apk/res/android\" android:layout_width=\"match_parent\" android:layout_height=\"match_parent\" />\n",
        )
        val debugAuditLayerOverride = if (explicitEmptyDebugResourceLayers) {
            """
                onVariants(selector().withName('demoDebug')) {
                    tasks.matching {
                        it.name == 'auditHardeningDemoDebug'
                    }.configureEach { audit ->
                        audit.appStaticResourceDirectories.set([])
                        audit.appStaticResourceLayerDirectoryCounts.set([0])
                        audit.appStaticResourceLayerIdentity.set(['0:'])
                        audit.appStaticResourceInputs.setFrom([])
                    }
                }
            """.trimIndent()
        } else {
            ""
        }
        app.resolve("build.gradle").writeText(
            """
            plugins {
                id 'com.android.application'
                id 'org.jetbrains.kotlin.android'
                id 'com.holin.android.hardening'
            }

            android {
                namespace = 'com.example.app'
                compileSdk = 35
                buildFeatures { buildConfig = true }
                signingConfigs {
                    fixture {
                        storeFile = rootProject.file('debug.keystore')
                        storePassword = 'android'
                        keyAlias = 'androiddebugkey'
                        keyPassword = 'android'
                        storeType = 'PKCS12'
                    }
                }
                defaultConfig {
                    applicationId = 'com.example.app'
                    minSdk = 26
                    targetSdk = 35
                    versionCode = 7
                    versionName = '1.0'
                    signingConfig = signingConfigs.fixture
                    proguardFiles 'proguard-rules.pro'
                }
                flavorDimensions += 'channel'
                productFlavors {
                    demo { dimension = 'channel' }
                }
                buildTypes {
                    debug { minifyEnabled = false }
                    release { minifyEnabled = true }
                }
                sourceSets {
                    main { res.srcDirs += 'src/main/res-extra' }
                }
            }

            dependencies {
                implementation project(':core')
                implementation project(':compress')
                implementation project(':selector')
                implementation project(':ucrop')
                implementation files('../libs/third.jar')
                implementation 'fixture:external-program:1.0'
            }

            androidHardening {
                enabled.set(providers.gradleProperty('androidHardening').map { it.toBoolean() }.orElse(false))
                projectKey.set('demo')
                variants.include('demoDebug')
                variants.include('demoRelease')
                ownership {
                    module(':app') { sourceSets.add('main') }
                    module(':core') { sourceSets.add('main') }
                    module(':compress') { sourceSets.add('main') }
                    module(':selector') { sourceSets.add('main') }
                    module(':ucrop') { sourceSets.add('main') }
                    excludedPackagePrefixes.add('com.vendor.excluded')
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
                mapping.storeDirectory.set(rootProject.layout.projectDirectory.dir('fixture-state'))
            }

            gradle.taskGraph.whenReady {
                tasks.matching { it.name.startsWith('auditHardening') }.configureEach {
                    legacyPluginObservations.set(rootProject.file('fixture-legacy-plugin-observations.txt').readLines())
                }
            }

            androidComponents {
                onVariants(selector().withName('demoDebug')) { variant ->
                    tasks.matching {
                        it.name == 'generateHardeningDemoDebugCodeMapping'
                    }.configureEach { hardening ->
                        hardening.doLast {
                            def expected = variant.compileClasspath.files.collect { it.canonicalPath }.toSet()
                            def actual = hardening.runtimeClasspath.files.collect { it.canonicalPath }.toSet()
                            if (!actual.containsAll(expected)) {
                                throw new GradleException(
                                    "hardening hierarchy classpath omits public variant.compileClasspath: " +
                                        "missing=${'$'}{(expected - actual).size()}"
                                )
                            }
                            def expectedResource = project.layout.projectDirectory
                                .dir('src/main/res-extra').asFile.canonicalFile
                            def actualResources = hardening.inputs.files.files.collect { it.canonicalFile }
                            if (!actualResources.contains(expectedResource)) {
                                throw new GradleException(
                                    'hardening static resource input omits app/src/main/res-extra: actual=' + actualResources
                                )
                            }
                            logger.lifecycle('hardening static resource input includes app/src/main/res-extra')
                        }
                    }
                }
                onVariants(selector().withName('demoRelease')) {
                    tasks.matching {
                        it.name == 'auditHardeningDemoRelease'
                    }.configureEach { audit ->
                        audit.doFirst {
                            def expectedResource = project.layout.projectDirectory
                                .dir('src/main/res').asFile.canonicalFile
                            def actualResources = audit.appStaticResourceInputs.files.collect { it.canonicalFile }
                            if (!actualResources.contains(expectedResource)) {
                                throw new GradleException(
                                    'release audit omitted explicitly owned main resources: actual=' + actualResources
                                )
                            }
                        }
                    }
                }
                $debugAuditLayerOverride
            }

            if (providers.gradleProperty('androidHardening').map { it.toBoolean() }.getOrElse(false)) {
                tasks.register('probeStaticResourceInputs') {
                    dependsOn('generateHardeningDemoDebugCodeMapping')
                    inputs.files(providers.provider {
                        tasks.named('generateHardeningDemoDebugCodeMapping').get().appStaticResourceInputs
                    })
                    outputs.file(layout.buildDirectory.file('probe/static-resource-inputs.txt'))
                    doLast {
                        outputs.files.singleFile.text = tasks
                            .named('generateHardeningDemoDebugCodeMapping')
                            .get()
                            .inputs
                            .files
                            .files
                            .collect { it.canonicalPath }
                            .sort()
                            .join('\n')
                    }
                }
            }

            def hardeningSha256 = { byte[] bytes ->
                java.security.MessageDigest.getInstance('SHA-256')
                    .digest(bytes)
                    .collect { String.format('%02x', it & 0xff) }
                    .join()
            }
            tasks.register('seedOldHardeningStates') {
                doLast {
                    def emptyRulesHash = hardeningSha256(new byte[0])
                    def oldConfiguration = hardeningSha256(
                        "r8-owned-code-optimization-stability-v1\n${'$'}emptyRulesHash".getBytes('UTF-8')
                    )
                    ['demoDebug', 'demoRelease'].eachWithIndex { variant, index ->
                        def store = new com.holin.android.hardening.state.StateStore()
                        def coordinates = new com.holin.android.hardening.state.StateCoordinates(
                            'demo', variant, 'com.example.app', 'com.example.app', oldConfiguration
                        )
                        def prepared = store.prepare(new com.holin.android.hardening.state.PrepareRequest(
                            rootProject.file("fixture-state/demo/${'$'}variant").toPath(),
                            coordinates,
                            rootProject.file("seed/${'$'}variant").toPath(),
                            (index == 0 ? 'a' : 'b') * 64,
                            true,
                            true,
                            true,
                        ))
                        store.archive(new com.holin.android.hardening.state.ArchiveRequest(
                            prepared,
                            index + 1,
                            (index == 0 ? 'c' : 'd') * 64,
                        ))
                    }
                }
            }
            """.trimIndent(),
        )
    }

    private fun writeLibraryBuild(module: String) {
        val simpleName = module.replaceFirstChar(Char::uppercaseChar)
        val directory = projectDirectory.resolve(module)
        directory.resolve("src/main/java/com/example/$module").createDirectories()
        directory.resolve("src/main/java/com/example/$module/$simpleName.java").writeText(
            "package com.example.$module; public final class $simpleName { public String beanValue; }\n",
        )
        if (module == "core") {
            directory.resolve("src/main/java/com/example/core/BaseActivity.java").writeText(
                """
                package com.example.core;
                public final class BaseActivity extends external.ExternalActivity {
                    public void handle(android.view.View view) {}
                    public void ordinary() {}
                }
                """.trimIndent() + "\n",
            )
        }
        directory.resolve("src/main/AndroidManifest.xml").writeText("<manifest />\n")
        directory.resolve("build.gradle").writeText(
            """
            plugins { id 'com.android.library' }

            android {
                namespace = 'com.example.$module'
                compileSdk = 35
                defaultConfig { minSdk = 26 }
                flavorDimensions += 'channel'
                productFlavors {
                    demo { dimension = 'channel' }
                }
            }

            ${if (module == "core") "dependencies { implementation files('../libs/external-android.aar') }" else ""}
            """.trimIndent(),
        )
    }

    private fun writeExternalJar() {
        val source = projectDirectory.resolve("external-src/third/External.java")
        source.parent.createDirectories()
        source.writeText("package third; public final class External {}\n")
        val classes = projectDirectory.resolve("external-classes").also { it.createDirectories() }
        val compiler = requireNotNull(javax.tools.ToolProvider.getSystemJavaCompiler())
        check(compiler.run(null, null, null, "-d", classes.toString(), source.toString()) == 0)
        val jarPath = projectDirectory.resolve("libs/third.jar")
        jarPath.parent.createDirectories()
        JarOutputStream(jarPath.toFile().outputStream()).use { jar ->
            jar.putNextEntry(JarEntry("third/External.class"))
            jar.write(Files.readAllBytes(classes.resolve("third/External.class")))
            jar.closeEntry()
        }
    }

    private fun writeExternalAndroidAar(sdk: String) {
        val source = projectDirectory.resolve("external-android-src/external/ExternalActivity.java")
        source.parent.createDirectories()
        source.writeText("package external; public class ExternalActivity extends android.app.Activity {}\n")
        val classes = projectDirectory.resolve("external-android-classes").also { it.createDirectories() }
        val compiler = requireNotNull(javax.tools.ToolProvider.getSystemJavaCompiler())
        check(
            compiler.run(
                null,
                null,
                null,
                "-classpath",
                Path.of(sdk, "platforms", "android-35", "android.jar").toString(),
                "-d",
                classes.toString(),
                source.toString(),
            ) == 0,
        )
        val classesJar = projectDirectory.resolve("external-android-classes.jar")
        JarOutputStream(classesJar.toFile().outputStream()).use { jar ->
            jar.putNextEntry(JarEntry("external/ExternalActivity.class"))
            jar.write(Files.readAllBytes(classes.resolve("external/ExternalActivity.class")))
            jar.closeEntry()
        }
        val aar = projectDirectory.resolve("libs/external-android.aar")
        JarOutputStream(aar.toFile().outputStream()).use { zip ->
            zip.putNextEntry(JarEntry("AndroidManifest.xml"))
            zip.write("<manifest package=\"external.fixture\" />\n".toByteArray())
            zip.closeEntry()
            zip.putNextEntry(JarEntry("classes.jar"))
            zip.write(Files.readAllBytes(classesJar))
            zip.closeEntry()
        }
    }

    private fun writeExternalProgramModule() {
        val source = projectDirectory.resolve("external-program-src/external/program/ExternalProgram.java")
        source.parent.createDirectories()
        source.writeText("package external.program; public final class ExternalProgram {}\n")
        val classes = projectDirectory.resolve("external-program-classes").also { it.createDirectories() }
        val compiler = requireNotNull(javax.tools.ToolProvider.getSystemJavaCompiler())
        check(compiler.run(null, null, null, "-d", classes.toString(), source.toString()) == 0)
        val artifactDirectory = projectDirectory.resolve("repo/fixture/external-program/1.0")
        artifactDirectory.createDirectories()
        listOf("external-program-1.0-api.jar", "external-program-1.0-runtime.jar").forEach { fileName ->
            JarOutputStream(artifactDirectory.resolve(fileName).toFile().outputStream()).use { jar ->
                jar.putNextEntry(JarEntry("external/program/ExternalProgram.class"))
                jar.write(Files.readAllBytes(classes.resolve("external/program/ExternalProgram.class")))
                jar.closeEntry()
            }
        }
        artifactDirectory.resolve("external-program-1.0.module").writeText(
            """
            {
              "formatVersion": "1.1",
              "component": { "group": "fixture", "module": "external-program", "version": "1.0" },
              "createdBy": { "gradle": { "version": "8.13" } },
              "variants": [
                {
                  "name": "apiElements",
                  "attributes": {
                    "artifactType": "jar",
                    "org.gradle.category": "library",
                    "org.gradle.dependency.bundling": "external",
                    "org.gradle.usage": "java-api"
                  },
                  "files": [
                    { "name": "external-program-1.0-api.jar", "url": "external-program-1.0-api.jar" }
                  ]
                },
                {
                  "name": "runtimeElements",
                  "attributes": {
                    "artifactType": "android-classes-jar",
                    "org.gradle.category": "library",
                    "org.gradle.dependency.bundling": "external",
                    "org.gradle.usage": "java-runtime"
                  },
                  "files": [
                    { "name": "external-program-1.0-runtime.jar", "url": "external-program-1.0-runtime.jar" }
                  ]
                }
              ]
            }
            """.trimIndent() + "\n",
        )
    }

    private fun seedOldDebugAndReleaseStates() {
        runner("seedOldHardeningStates").build()
    }

    private fun canonicalTreeHash(root: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.walk(root).use { paths ->
            paths.sorted().forEach { path ->
                val relative = root.relativize(path).toString()
                digest.update(relative.toByteArray())
                if (Files.isRegularFile(path)) digest.update(Files.readAllBytes(path))
            }
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private fun stateRoot(variant: String): Path = projectDirectory.resolve("fixture-state/demo/$variant")

    private fun createFixtureKeyStore() {
        val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool")
        val process = ProcessBuilder(
            keytool.toString(),
            "-genkeypair",
            "-alias",
            "androiddebugkey",
            "-keystore",
            projectDirectory.resolve("debug.keystore").toString(),
            "-storepass",
            "android",
            "-keypass",
            "android",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "3650",
            "-dname",
            "CN=Android Debug,O=Android,C=US",
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

    private companion object {
        val LIBRARY_MODULES = listOf("core", "compress", "selector", "ucrop")
    }
}
