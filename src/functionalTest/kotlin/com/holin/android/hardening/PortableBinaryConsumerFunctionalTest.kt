package com.holin.android.hardening

import com.android.apksig.ApkVerifier
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.holin.android.hardening.naming.RegistryCodec
import com.holin.android.hardening.naming.RegistrySnapshot
import com.holin.android.hardening.verification.MappingSymbolKey
import com.holin.android.hardening.verification.R8MappingParser
import java.awt.image.BufferedImage
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.Date
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import java.util.zip.Adler32
import java.util.zip.ZipFile
import javax.imageio.ImageIO
import kotlin.io.path.createDirectories
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.gradle.testkit.runner.GradleRunner
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.jupiter.api.io.TempDir

class PortableBinaryConsumerFunctionalTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `offline arbitrary Android project resolves only the extracted Maven plugin`() {
        verifyOfflineConsumer("agp-8.13.2", "8.13.2", "2.3.0", "8.13", "8.13.19")
    }

    @Test
    fun `offline minimum available Android project resolves only the extracted Maven plugin`() {
        verifyOfflineConsumer("agp-8.10.1", "8.10.1", "2.3.0", "8.11.1", "8.10.24")
    }

    @Test
    fun `offline minimum supported Android project resolves only the extracted Maven plugin`() {
        verifyOfflineConsumer("agp-8.8.0", "8.8.0", "2.3.0", "8.10.2", null)
    }

    @Test
    fun `fixed seed keeps all hardening artifact bytes stable across clean executions`() {
        val temporary = projectDirectory
        projectDirectory = temporary.resolve("first-fresh-root").also(Path::createDirectories)
        val gradle = prepareOfflineFixture("agp-8.13.2", "8.13.2", "2.3.0", "8.13")
        val fixedSeed = listOf("-PandroidHardeningFixedSeed=h3-portable-fixed-seed")

        val first = runOfflineGradle(gradle, fixedSeed)
        assertSuccessfulOfflineBuild(first)
        val firstHashes = hardeningArtifactHashes()

        projectDirectory = temporary.resolve("second-fresh-root").also(Path::createDirectories)
        val secondGradle = prepareOfflineFixture("agp-8.13.2", "8.13.2", "2.3.0", "8.13")
        val second = runOfflineGradle(secondGradle, fixedSeed)
        assertSuccessfulOfflineBuild(second)
        val secondHashes = hardeningArtifactHashes()

        assertEquals(firstHashes, secondHashes)
        verifyConsumerArtifacts("8.13.19")
    }

    @Test
    fun `secure random executions keep mapping stable while hardened artifacts rotate`() {
        val gradle = prepareOfflineFixture("agp-8.13.2", "8.13.2", "2.3.0", "8.13")

        val warmup = runOfflineGradle(gradle)
        assertSuccessfulOfflineBuild(warmup)
        cleanConsumerExecution(true)

        val first = runOfflineGradle(gradle)
        assertSuccessfulOfflineBuild(first)
        val firstHashes = hardeningArtifactHashes()
        val firstRegistry = hardeningRegistrySnapshot()
        val firstApplyMapping = hardeningApplyMappingSemantics()

        cleanConsumerExecution(true)
        val second = runOfflineGradle(gradle)
        assertSuccessfulOfflineBuild(second)
        val secondHashes = hardeningArtifactHashes()
        val secondRegistry = hardeningRegistrySnapshot()
        val secondApplyMapping = hardeningApplyMappingSemantics()

        assertEquals(
            firstHashes.getValue("build/outputs/mapping/demoQa/mapping.txt"),
            secondHashes.getValue("build/outputs/mapping/demoQa/mapping.txt"),
        )
        assertEquals(
            firstRegistry.schemaVersion,
            secondRegistry.schemaVersion,
        )
        assertEquals(
            firstRegistry.seedSha256,
            secondRegistry.seedSha256,
        )
        assertEquals(
            firstRegistry.assignments,
            secondRegistry.assignments,
        )
        assertEquals(
            firstRegistry.tombstones,
            secondRegistry.tombstones,
        )
        assertEquals(
            firstRegistry.generation + 1L,
            secondRegistry.generation,
        )
        assertNotEquals(
            firstHashes.getValue("build/hardening/demoQa/registry.json"),
            secondHashes.getValue("build/hardening/demoQa/registry.json"),
        )
        assertNotEquals(
            firstHashes.getValue("build/hardening/demoQa/applymapping.pro"),
            secondHashes.getValue("build/hardening/demoQa/applymapping.pro"),
        )
        assertEquals(firstApplyMapping, secondApplyMapping)
        assertNotEquals(
            firstHashes.getValue("build/outputs/hardening/demoQa/demoQa-hardened.aab"),
            secondHashes.getValue("build/outputs/hardening/demoQa/demoQa-hardened.aab"),
        )
        assertNotEquals(
            firstHashes.getValue("build/outputs/hardening/demoQa/demoQa-hardened-universal.apk"),
            secondHashes.getValue("build/outputs/hardening/demoQa/demoQa-hardened-universal.apk"),
        )
        verifyConsumerArtifacts("8.13.19")
    }

    @Test
    fun `exact portable ZIP carries verification metadata and is embedded unchanged for consumers`() {
        val portable = Path.of(
            requireNotNull(System.getProperty("portable.plugin.archive")) {
                "portable.plugin.archive test property is required"
            },
        ).toAbsolutePath().normalize()
        val offline = Path.of(
            requireNotNull(System.getProperty("portable.offline.testkit.archive")) {
                "portable.offline.testkit.archive test property is required"
            },
        ).toAbsolutePath().normalize()

        ZipFile(portable.toFile()).use { zip ->
            val metadata = requireNotNull(zip.getEntry("verification-metadata.xml")) {
                "portable ZIP must package dependency verification metadata"
            }
            val text = zip.getInputStream(metadata).bufferedReader().readText()
            assertContains(text, "<verify-metadata>true</verify-metadata>")
            assertContains(text, "group=\"com.holin.android.hardening\" name=\"hardening-gradle-plugin\"")
        }
        ZipFile(offline.toFile()).use { zip ->
            val embedded = requireNotNull(zip.getEntry("portable/${portable.fileName}")) {
                "offline TestKit must embed the exact portable ZIP"
            }
            assertEquals(sha256(portable), zip.getInputStream(embedded).use(::sha256))
        }
    }

    @Test
    fun `exact portable ZIP isolates bundletool runtime from the AGP plugin classloader`() {
        val gradle = prepareOfflineFixture("agp-8.13.2", "8.13.2", "2.3.0", "8.13")

        val result = runOfflineGradle(gradle)

        assertSuccessfulOfflineBuild(result)
        verifyConsumerArtifacts("8.13.19")
    }

    @Test
    fun `offline TestKit publishes verified templates metadata checksums and safe paths`() {
        val archive = Path.of(
            requireNotNull(System.getProperty("portable.offline.testkit.archive")) {
                "portable.offline.testkit.archive test property is required"
            },
        ).toAbsolutePath().normalize()
        ZipFile(archive.toFile()).use { zip ->
            val entries = zip.entries().asSequence().filterNot { entry -> entry.isDirectory }.toList()
            val names = entries.map { entry -> entry.name }
            val required = listOf(
                "SHA256SUMS",
                "MATRIX-MANIFEST.txt",
                "FIXTURE-MANIFEST.txt",
                "fixture-templates/settings.gradle.template",
                "fixture-templates/build.gradle.template",
                "fixture-templates/mobile.gradle.template",
                "matrix/agp-8.8.0/verification-metadata.xml",
                "matrix/agp-8.10.1/verification-metadata.xml",
                "matrix/agp-8.13.2/verification-metadata.xml",
                "portable/${Path.of(requireNotNull(System.getProperty("portable.plugin.archive"))).fileName}",
            )
            required.forEach { name -> assertTrue(name in names, "offline TestKit is missing $name") }
            listOf(
                "matrix/agp-8.8.0/verification-metadata.xml" to "8.8.0",
                "matrix/agp-8.10.1/verification-metadata.xml" to "8.10.1",
                "matrix/agp-8.13.2/verification-metadata.xml" to "8.13.2",
            ).forEach { (path, version) ->
                val metadata = zip.getInputStream(zip.getEntry(path)).bufferedReader().readText()
                assertContains(metadata, "<verify-metadata>true</verify-metadata>")
                assertContains(metadata, "group=\"com.android.tools.build\" name=\"gradle\" version=\"$version\"")
            }
            val forbidden = listOf(
                ".jks", ".keystore", ".p12", ".hardening/", "mapping.txt", "baseline.json",
                "demo", ".git/", ".gradle-home/", "/build/outputs/",
            )
            assertTrue(
                names.none { name -> forbidden.any(name.lowercase()::contains) },
                "offline TestKit contains a sensitive path",
            )
            val checksums = zip.getInputStream(zip.getEntry("SHA256SUMS"))
                .bufferedReader()
                .readLines()
                .filter(String::isNotBlank)
                .associate { line -> line.substringAfter("  ") to line.substringBefore("  ") }
            assertEquals(names.filterNot { name -> name == "SHA256SUMS" }.sorted(), checksums.keys.sorted())
            entries.filterNot { entry -> entry.name == "SHA256SUMS" }.forEach { entry ->
                assertEquals(checksums.getValue(entry.name), zip.getInputStream(entry).use(::sha256))
            }
        }
    }

    private fun verifyOfflineConsumer(
        rowId: String,
        agpVersion: String,
        kotlinVersion: String,
        gradleVersion: String,
        expectedR8Version: String?,
    ) {
        val gradle = prepareOfflineFixture(rowId, agpVersion, kotlinVersion, gradleVersion)
        val result = runOfflineGradle(gradle)

        assertSuccessfulOfflineBuild(result)
        verifyConsumerArtifacts(expectedR8Version)
    }

    private fun prepareOfflineFixture(
        rowId: String,
        agpVersion: String,
        kotlinVersion: String,
        gradleVersion: String,
    ): Path {
        val archive = Path.of(
            requireNotNull(System.getProperty("portable.offline.testkit.archive")) {
                "portable.offline.testkit.archive test property is required"
            },
        ).toAbsolutePath().normalize()
        assertTrue(Files.isRegularFile(archive), "portable archive is missing: $archive")
        val extraction = projectDirectory.resolve("offline-testkit")
        extract(archive, extraction)
        val matrixManifest = extraction.resolve("MATRIX-MANIFEST.txt").readText()
        assertContains(matrixManifest, "schema=holin-offline-matrix-v1")
        val rowManifest = matrixManifest.lineSequence()
            .single { line -> line.startsWith("available|agp=$agpVersion|gradle=$gradleVersion|kotlin=$kotlinVersion|") }
        assertTrue(rowManifest.endsWith("|repository=matrix/$rowId/repository"), rowManifest)
        val matrix = extraction.resolve("matrix/$rowId")
        val gradle = matrix.resolve("gradle/gradle-$gradleVersion")
        val portableRepository = extractPortableRepository(extraction)
        mergeRepository(matrix.resolve("repository"), portableRepository)
        Files.copy(
            matrix.resolve("verification-metadata.xml"),
            portableRepository.parent.resolve("verification-metadata.xml"),
            REPLACE_EXISTING,
        )
        writeFixture(portableRepository, false, agpVersion, kotlinVersion, gradle)
        initializeFixtureGitRepository()
        generateSigningMaterial()

        val settings = projectDirectory.resolve("settings.gradle").readText()
        assertFalse(settings.contains("includeBuild"), "binary fixture must not use source substitution")
        val repositoryUrls = Regex("""url\s*=\s*uri\('([^']+)'\)""")
            .findAll(settings)
            .map { match -> match.groupValues[1] }
            .toList()
        assertEquals(2, repositoryUrls.size, settings)
        assertTrue(repositoryUrls.all { url -> url.startsWith("file:") }, settings)
        assertEquals(1, repositoryUrls.distinct().size, settings)
        assertFalse(settings.contains("google()") || settings.contains("mavenCentral()"), settings)
        return gradle.resolve("bin/gradle")
    }

    private fun assertSuccessfulOfflineBuild(result: ConsumerResult) {
        assertEquals(0, result.exitCode, result.output)
        assertContains(result.output, "BUILD SUCCESSFUL")
        assertContains(result.output, "HARDENING_BUNDLETOOL_WORKER_RUNTIME=")
        assertFalse(result.output.contains("includeBuild"))
        assertEquals(listOf("--offline", "--no-daemon"), result.command.filter { argument ->
            argument == "--offline" || argument == "--no-daemon"
        })
        assertFalse(result.gradleUserHomeExistedBeforeLaunch)
        assertEquals(projectDirectory.resolve("empty-gradle-home"), result.gradleUserHome)
        listOf(
            "Downloading http://",
            "Downloading https://",
            "Could not GET",
            "Could not HEAD",
            "Received status code ",
            "HTTP response code: ",
        ).forEach { networkFailure ->
            assertFalse(result.output.contains(networkFailure), result.output)
        }
    }

    @Test
    fun `hardening declared before Android and Kotlin configures without linkage failure`() {
        val archive = Path.of(
            requireNotNull(System.getProperty("portable.offline.testkit.archive")) {
                "portable.offline.testkit.archive test property is required"
            },
        ).toAbsolutePath().normalize()
        val extraction = projectDirectory.resolve("offline-testkit-before-android")
        extract(archive, extraction)
        val portableRepository = extractPortableRepository(extraction)
        val matrix = extraction.resolve("matrix/agp-8.13.2")
        mergeRepository(matrix.resolve("repository"), portableRepository)
        Files.copy(
            matrix.resolve("verification-metadata.xml"),
            portableRepository.parent.resolve("verification-metadata.xml"),
            REPLACE_EXISTING,
        )
        writeFixture(
            portableRepository,
            true,
            "8.13.2",
            "2.3.0",
        )

        val result = GradleRunner.create()
            .withProjectDir(projectDirectory.toFile())
            .withTestKitDir(projectDirectory.resolve("fresh-testkit-home").toFile())
            .withEnvironment(System.getenv().toMutableMap().also { environment ->
                environment.remove("GRADLE_RO_DEP_CACHE")
            })
            .withArguments("--offline", "--stacktrace", ":mobile:tasks", "--all")
            .buildAndFail()

        assertTrue(result.output.contains("Kotlin Android plugin version is incompatible: actual=not applied"), result.output)
        assertFalse(result.output.contains("NoClassDefFoundError"), result.output)
        assertFalse(result.output.contains("LinkageError"), result.output)
    }

    private fun writeFixture(
        repository: Path,
        hardeningBeforeAndroid: Boolean = false,
        agpVersion: String = "8.13.2",
        kotlinVersion: String = "2.3.0",
        gradleDistribution: Path? = null,
    ) {
        val sdk = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
        require(!sdk.isNullOrBlank()) { "ANDROID_HOME or ANDROID_SDK_ROOT is required" }
        val repositoryUrl = repository.toUri().toString()
        val neutralLegacyJarSha256 = gradleDistribution?.let { distribution ->
            packageNeutralLegacyPlugin(repository, distribution)
        }
        val verificationMetadata = repository.parent.resolve("verification-metadata.xml")
        if (Files.isRegularFile(verificationMetadata)) {
            val gradleDirectory = projectDirectory.resolve("gradle").also(Path::createDirectories)
            Files.copy(verificationMetadata, gradleDirectory.resolve("verification-metadata.xml"), REPLACE_EXISTING)
        }
        projectDirectory.resolve("settings.gradle").writeText(
            """
            pluginManagement {
                repositories {
                    maven { url = uri('$repositoryUrl') }
                }
            }
            if (System.getenv('GRADLE_RO_DEP_CACHE') != null) {
                throw new GradleException('GRADLE_RO_DEP_CACHE must be unset for the offline fixture')
            }
            dependencyResolutionManagement {
                repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
                repositories {
                    maven { url = uri('$repositoryUrl') }
                }
            }
            rootProject.name = 'portable-hardening-consumer'
            include ':mobile', ':core', ':media'
            """.trimIndent(),
        )
        projectDirectory.resolve("local.properties")
            .writeText("sdk.dir=${sdk.replace("\\", "\\\\")}\n")
        if (neutralLegacyJarSha256 != null) {
            projectDirectory.resolve("gradle").createDirectories()
            projectDirectory.resolve("gradle/libs.versions.toml")
                .writeText("[versions]\nneutralLegacy = \"$NEUTRAL_LEGACY_VERSION\"\n")
        }
        projectDirectory.resolve("build.gradle").writeText(
            """
            plugins {
                id 'com.android.application' version '$agpVersion' apply false
                id 'com.android.library' version '$agpVersion' apply false
                id 'org.jetbrains.kotlin.android' version '$kotlinVersion' apply false
                ${if (neutralLegacyJarSha256 != null) "id '$NEUTRAL_LEGACY_PLUGIN_ID' version '$NEUTRAL_LEGACY_VERSION' apply false" else ""}
            }
            """.trimIndent(),
        )
        listOf("core", "media").forEach { module ->
            val directory = projectDirectory.resolve(module)
            directory.createDirectories()
            directory.resolve("build.gradle").writeText(
                """
                plugins {
                    id 'com.android.library'
                    id 'org.jetbrains.kotlin.android'
                }
                android {
                    namespace 'com.example.$module'
                    compileSdk 35
                    defaultConfig { minSdk 26 }
                    flavorDimensions 'brand'
                    productFlavors { demo { dimension 'brand' } }
                    buildTypes { qa { minifyEnabled false } }
                    compileOptions {
                        sourceCompatibility JavaVersion.VERSION_17
                        targetCompatibility JavaVersion.VERSION_17
                    }
                }
                """.trimIndent(),
            )
            directory.resolve("src/main/AndroidManifest.xml").also { manifest ->
                manifest.parent.createDirectories()
                manifest.writeText("<manifest />\n")
            }
            val extension = if (module == "core") "java" else "kt"
            directory.resolve("src/main/java/com/example/$module/${module.replaceFirstChar(Char::uppercase)}Owned.$extension")
                .also { source ->
                    source.parent.createDirectories()
                    source.writeText(
                        if (extension == "java") {
                            "package com.example.$module; public final class CoreOwned { public int value() { return 17; } }\n"
                        } else {
                            "package com.example.$module\nclass MediaOwned { fun value(): Int = 23 }\n"
                        },
                    )
                }
        }
        val mobile = projectDirectory.resolve("mobile")
        mobile.resolve("src/main/AndroidManifest.xml").also { manifest ->
            manifest.parent.createDirectories()
            manifest.writeText(
                """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                    <application>
                        <activity android:name="com.example.owned.MainActivity" android:exported="true">
                            <intent-filter>
                                <action android:name="android.intent.action.MAIN" />
                                <category android:name="android.intent.category.LAUNCHER" />
                            </intent-filter>
                        </activity>
                    </application>
                </manifest>
                """.trimIndent() + "\n",
            )
        }
        mobile.resolve("src/production-java/com/example/owned/OwnedJava.java").also { source ->
            source.parent.createDirectories()
            source.writeText(
                "package com.example.owned; public final class OwnedJava { public String message() { return \"owned-java\"; } }\n",
            )
        }
        mobile.resolve("src/production-kotlin/com/example/owned/OwnedKotlin.kt").also { source ->
            source.parent.createDirectories()
            source.writeText("package com.example.owned\nclass OwnedKotlin { fun message(): String = \"owned-kotlin\" }\n")
        }
        mobile.resolve("src/production-kotlin/com/example/owned/MainActivity.kt").also { source ->
            source.parent.createDirectories()
            source.writeText(
                """
                package com.example.owned

                import android.app.Activity
                import android.os.Bundle
                import com.example.core.CoreOwned
                import com.example.media.MediaOwned

                class MainActivity : Activity() {
                    override fun onCreate(savedInstanceState: Bundle?) {
                        super.onCreate(savedInstanceState)
                        title = OwnedJava().message() + OwnedKotlin().message() + CoreOwned().value() + MediaOwned().value()
                    }
                }
                """.trimIndent() + "\n",
            )
        }
        mobile.resolve("src/production-res/layout/owned_fixture.xml").also { resource ->
            resource.parent.createDirectories()
            resource.writeText(
                "<LinearLayout xmlns:android=\"http://schemas.android.com/apk/res/android\" android:layout_width=\"match_parent\" android:layout_height=\"match_parent\" />\n",
            )
        }
        mobile.resolve("src/production-res/drawable/owned_fixture.webp").also { resource ->
            resource.parent.createDirectories()
            val image = BufferedImage(4, 4, BufferedImage.TYPE_INT_ARGB)
            for (y in 0 until image.height) for (x in 0 until image.width) {
                image.setRGB(x, y, if ((x + y) % 2 == 0) 0xff336699.toInt() else 0xffcc8844.toInt())
            }
            assertTrue(ImageIO.write(image, "webp", resource.toFile()), "functional test WebP writer is unavailable")
        }
        mobile.resolve("proguard-rules.pro").writeText("-dontwarn com.example.missing.**\n")
        mobile.resolve("build.gradle").writeText(
            """
            plugins {
                ${if (hardeningBeforeAndroid) "id 'com.holin.android.hardening' version '1.3.0'" else "id 'com.android.application'"}
                ${if (hardeningBeforeAndroid) "id 'com.android.application'" else "id 'org.jetbrains.kotlin.android'"}
                ${if (hardeningBeforeAndroid) "id 'org.jetbrains.kotlin.android'" else "id 'com.holin.android.hardening' version '1.3.0'"}
                ${if (neutralLegacyJarSha256 != null) "id '$NEUTRAL_LEGACY_PLUGIN_ID'" else ""}
            }
            dependencies {
                implementation project(':core')
                implementation project(':media')
            }
            android {
                namespace 'com.example.mobile'
                compileSdk 35
                defaultConfig {
                    applicationId 'com.example.mobile'
                    minSdk 26
                    targetSdk 35
                    versionCode 1
                    versionName '1.0'
                }
                compileOptions {
                    sourceCompatibility JavaVersion.VERSION_17
                    targetCompatibility JavaVersion.VERSION_17
                }
                flavorDimensions 'brand'
                productFlavors { demo { dimension 'brand' } }
                signingConfigs {
                    fixture {
                        storeFile file('fixture-signing.p12')
                        storePassword 'fixture-password'
                        keyAlias 'fixture-key'
                        keyPassword 'fixture-password'
                        storeType 'PKCS12'
                    }
                }
                buildTypes {
                    qa {
                        minifyEnabled true
                        signingConfig signingConfigs.fixture
                        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
                    }
                }
                sourceSets {
                    demo.java.setSrcDirs(['src/production-java'])
                    demo.kotlin.setSrcDirs(['src/production-kotlin'])
                    demo.res.setSrcDirs(['src/production-res'])
                }
            }
            androidHardening {
                enabled.set(providers.gradleProperty('androidHardening').map(String.&toBoolean).orElse(false))
                projectKey.set('portable-demo')
                variants.include('demoQa')
                ownership {
                    module(':mobile') { sourceSets.addAll('main', 'demo') }
                    module(':core') { sourceSets.add('main') }
                    module(':media') { sourceSets.add('main') }
                }
                rules { sourceFiles.from('proguard-rules.pro') }
                ${if (neutralLegacyJarSha256 != null) """
                legacyPlugins {
                    baselineFile.set(rootProject.layout.projectDirectory.file('legacy/neutral-legacy-baseline.json'))
                    plugin('neutralFixture') {
                        pluginId.set('$NEUTRAL_LEGACY_PLUGIN_ID')
                        expectedVersion.set('$NEUTRAL_LEGACY_VERSION')
                        configurationInputs.from(
                            rootProject.layout.projectDirectory.file('gradle/libs.versions.toml'),
                            layout.projectDirectory.file('build.gradle'),
                        )
                        mappingPaths.from(layout.buildDirectory.file('outputs/mapping/demoQa/mapping.txt'))
                    }
                }
                """.trimIndent() else "legacyPlugins { verifyCompatibility.set(false) }"}
                compatibility { autoMigrateLegacyState.set(false) }
                reproducibility {
                    fixedSeed.set(providers.gradleProperty('androidHardeningFixedSeed'))
                }
            }
            tasks.configureEach { task ->
                if (task.name != 'assembleHardeningDemoQaUniversalApk') return
                doFirst {
                    def files = bundletoolWorkerClasspath.files
                    def names = files.collect { it.name }.toSet()
                    def required = [
                        'bundletool-1.18.1.jar',
                        'aapt2-proto-8.13.2-14304508.jar',
                        'auto-value-annotations-1.6.2.jar',
                        'jsr305-3.0.2.jar',
                        'gson-2.8.9.jar',
                        'dagger-2.28.3.jar',
                        'error_prone_annotations-2.18.0.jar',
                        'failureaccess-1.0.1.jar',
                        'guava-32.0.1-jre.jar',
                        'listenablefuture-9999.0-empty-to-avoid-conflict-with-guava.jar',
                        'j2objc-annotations-2.8.jar',
                        'protobuf-java-util-3.22.3.jar',
                        'protobuf-java-3.25.5.jar',
                        'javax.inject-1.jar',
                        'jose4j-0.9.5.jar',
                        'checker-qual-3.33.0.jar',
                        'slf4j-api-1.7.30.jar',
                    ] as Set
                    if (!names.containsAll(required)) {
                        throw new GradleException('bundletool worker runtime is incomplete: ' + (required - names).sort())
                    }
                    def gradleHome = gradle.gradleUserHomeDir.toPath().toRealPath()
                    def portableRepository = rootProject.file('portable-maven/repository')
                        .toPath().toRealPath()
                    def runtimeOutsidePortable = files.findAll { file ->
                        required.contains(file.name) &&
                            !file.toPath().toRealPath().startsWith(portableRepository)
                    }
                    if (!runtimeOutsidePortable.isEmpty()) {
                        throw new GradleException('bundletool worker runtime escaped exact portable repository: ' + runtimeOutsidePortable)
                    }
                    def outsideOfflineBoundary = files.findAll { file ->
                        def path = file.toPath().toRealPath()
                        !path.startsWith(portableRepository) && !path.startsWith(gradleHome)
                    }
                    if (!outsideOfflineBoundary.isEmpty()) {
                        throw new GradleException('bundletool worker classpath used a host cache fallback: ' + outsideOfflineBoundary)
                    }
                    println('HARDENING_BUNDLETOOL_WORKER_RUNTIME=' + names.sort().join(','))
                }
            }
            """.trimIndent(),
        )
        if (neutralLegacyJarSha256 != null) {
            writeNeutralLegacyBaseline(neutralLegacyJarSha256)
        }
    }

    private fun packageNeutralLegacyPlugin(repository: Path, gradleDistribution: Path): String {
        val sourceRoot = projectDirectory.resolve("fixture/neutral-legacy-plugin/src/com/holin/fixture")
        sourceRoot.createDirectories()
        sourceRoot.resolve("NeutralLegacyPlugin.java").writeText(
            """
            package com.holin.fixture;

            import org.gradle.api.Plugin;
            import org.gradle.api.Project;

            public final class NeutralLegacyPlugin implements Plugin<Project> {
                @Override
                public void apply(Project project) {
                    project.getExtensions().add("neutralLegacy", new NeutralLegacyExtension());
                    project.getTasks().register("neutralLegacyProbe", NeutralLegacyTask.class);
                }
            }
            """.trimIndent(),
        )
        sourceRoot.resolve("NeutralLegacyExtension.java").writeText(
            """
            package com.holin.fixture;

            public final class NeutralLegacyExtension {
            }
            """.trimIndent(),
        )
        sourceRoot.resolve("NeutralLegacyTask.java").writeText(
            """
            package com.holin.fixture;

            import org.gradle.api.DefaultTask;

            public abstract class NeutralLegacyTask extends DefaultTask {
            }
            """.trimIndent(),
        )

        val classes = projectDirectory.resolve("fixture/neutral-legacy-plugin/classes")
        classes.createDirectories()
        val classpath = Files.walk(gradleDistribution.resolve("lib")).use { paths ->
            paths.filter(Files::isRegularFile)
                .filter { path -> path.fileName.toString().endsWith(".jar") }
                .sorted()
                .map(Path::toString)
                .toList()
                .joinToString(java.io.File.pathSeparator)
        }
        val compiler = Path.of(System.getProperty("java.home"), "bin", "javac")
        val sources = Files.list(sourceRoot).use { paths ->
            paths.filter { path -> path.fileName.toString().endsWith(".java") }
                .sorted()
                .map(Path::toString)
                .toList()
        }
        val process = ProcessBuilder(
            listOf(compiler.toString(), "-classpath", classpath, "-d", classes.toString()) + sources,
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        assertEquals(0, process.waitFor(), output)

        val component = repository.resolve(
            "${NEUTRAL_LEGACY_GROUP.replace('.', '/')}/$NEUTRAL_LEGACY_MODULE/$NEUTRAL_LEGACY_VERSION",
        )
        component.createDirectories()
        val jar = component.resolve("$NEUTRAL_LEGACY_MODULE-$NEUTRAL_LEGACY_VERSION.jar")
        JarOutputStream(Files.newOutputStream(jar)).use { outputJar ->
            val entries = Files.walk(classes).use { paths ->
                paths.filter(Files::isRegularFile).sorted().toList()
            }
            entries.forEach { path ->
                val entry = JarEntry(classes.relativize(path).toString().replace(java.io.File.separatorChar, '/'))
                entry.time = 0L
                outputJar.putNextEntry(entry)
                Files.copy(path, outputJar)
                outputJar.closeEntry()
            }
            val marker = JarEntry("META-INF/gradle-plugins/$NEUTRAL_LEGACY_PLUGIN_ID.properties")
            marker.time = 0L
            outputJar.putNextEntry(marker)
            outputJar.write("implementation-class=com.holin.fixture.NeutralLegacyPlugin\n".toByteArray())
            outputJar.closeEntry()
        }
        component.resolve("$NEUTRAL_LEGACY_MODULE-$NEUTRAL_LEGACY_VERSION.pom").writeText(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>$NEUTRAL_LEGACY_GROUP</groupId>
              <artifactId>$NEUTRAL_LEGACY_MODULE</artifactId>
              <version>$NEUTRAL_LEGACY_VERSION</version>
              <packaging>jar</packaging>
              <name>Neutral fixture legacy plugin</name>
            </project>
            """.trimIndent(),
        )
        val markerGroup = NEUTRAL_LEGACY_PLUGIN_ID
        val markerModule = "$NEUTRAL_LEGACY_PLUGIN_ID.gradle.plugin"
        val marker = repository.resolve(
            "${markerGroup.replace('.', '/')}/$markerModule/$NEUTRAL_LEGACY_VERSION",
        )
        marker.createDirectories()
        marker.resolve("$markerModule-$NEUTRAL_LEGACY_VERSION.pom").writeText(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>$markerGroup</groupId>
              <artifactId>$markerModule</artifactId>
              <version>$NEUTRAL_LEGACY_VERSION</version>
              <packaging>pom</packaging>
              <name>Neutral fixture legacy plugin marker</name>
              <dependencies>
                <dependency>
                  <groupId>$NEUTRAL_LEGACY_GROUP</groupId>
                  <artifactId>$NEUTRAL_LEGACY_MODULE</artifactId>
                  <version>$NEUTRAL_LEGACY_VERSION</version>
                  <scope>runtime</scope>
                </dependency>
              </dependencies>
            </project>
            """.trimIndent(),
        )
        return sha256(jar)
    }

    private fun writeNeutralLegacyBaseline(jarSha256: String) {
        val fixtureBuild = projectDirectory.resolve("mobile/build.gradle")
        val frozenLine = "id '$NEUTRAL_LEGACY_PLUGIN_ID'\n"
        val baseline = projectDirectory.resolve("legacy/neutral-legacy-baseline.json")
        baseline.parent.createDirectories()
        baseline.writeText(
            """
            {
              "schemaVersion": 3,
              "capture": {
                "hashAlgorithm": "SHA-256",
                "encoding": "UTF-8",
                "lineEndings": "raw",
                "regionBoundary": "start-inclusive-end-exclusive",
                "sourceProvenance": {
                  "fixtureBuild": {
                    "path": "mobile/build.gradle",
                    "sourceRevision": "git-blob:${sha256(fixtureBuild)}",
                    "sha256": "${sha256(fixtureBuild)}"
                  }
                },
                "regions": {
                  "neutralLegacyApply": {
                    "file": "fixtureBuild",
                    "algorithm": "ordered-exact-lines",
                    "lines": ["${frozenLine.replace("\\", "\\\\").replace("\n", "\\n").replace("\"", "\\\"")}"]
                  }
                }
              },
              "frozenRegions": {
                "neutralLegacyApply": {
                  "file": "fixtureBuild",
                  "lineCount": 1,
                  "sha256": "${sha256(frozenLine.toByteArray())}"
                }
              },
              "versionSources": {
                "neutralLegacy": {
                  "path": "gradle/libs.versions.toml",
                  "literal": "neutralLegacy = \"$NEUTRAL_LEGACY_VERSION\""
                }
              },
              "plugins": [
                {
                  "name": "neutralFixture",
                  "pluginId": "$NEUTRAL_LEGACY_PLUGIN_ID",
                  "expectedVersion": "$NEUTRAL_LEGACY_VERSION",
                  "implementationClass": "com.holin.fixture.NeutralLegacyPlugin",
                  "jarSha256": "$jarSha256",
                  "extensionName": "neutralLegacy",
                  "extensionClass": "com.holin.fixture.NeutralLegacyExtension",
                  "taskNames": ["neutralLegacyProbe"],
                  "taskClasses": [
                    "com.holin.fixture.NeutralLegacyTask",
                    "com.holin.fixture.NeutralLegacyTask_Decorated",
                    "java.lang.Object",
                    "org.gradle.api.DefaultTask",
                    "org.gradle.api.internal.AbstractTask"
                  ],
                  "configurationInputs": ["gradle/libs.versions.toml", "mobile/build.gradle"],
                  "mappingPaths": ["mobile/build/outputs/mapping/demoQa/mapping.txt"],
                  "frozenRegions": ["neutralLegacyApply"],
                  "versionSources": ["neutralLegacy"]
                }
              ]
            }
            """.trimIndent() + "\n",
        )
    }

    private fun sha256(path: Path): String = sha256(Files.readAllBytes(path))

    private fun sha256(input: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte) }

    private fun generateSigningMaterial() {
        val random = SecureRandom.getInstance("SHA1PRNG").apply {
            setSeed(MessageDigest.getInstance("SHA-256").digest("holin-offline-fixture-signing-v1".toByteArray()))
        }
        val keyPair = KeyPairGenerator.getInstance("RSA").run {
            initialize(2048, random)
            generateKeyPair()
        }
        val subject = X500Name("CN=Offline Fixture,OU=Test,O=Neutral,L=Local,ST=Local,C=US")
        val certificate = JcaX509CertificateConverter().getCertificate(
            JcaX509v3CertificateBuilder(
                subject,
                BigInteger("104729"),
                Date.from(Instant.parse("2024-01-01T00:00:00Z")),
                Date.from(Instant.parse("2034-01-01T00:00:00Z")),
                subject,
                keyPair.public,
            ).build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)),
        )
        val password = "fixture-password".toCharArray()
        val keyStore = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("fixture-key", keyPair.private, password, arrayOf(certificate))
        }
        Files.newOutputStream(projectDirectory.resolve("mobile/fixture-signing.p12")).use { output ->
            keyStore.store(output, password)
        }
    }

    private fun initializeFixtureGitRepository() {
        val process = ProcessBuilder("git", "init", "--quiet")
            .directory(projectDirectory.toFile())
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        assertEquals(0, process.waitFor(), output)
    }

    private fun runOfflineGradle(
        gradle: Path,
        extraArguments: List<String> = emptyList(),
    ): ConsumerResult {
        assertTrue(Files.isRegularFile(gradle), "packaged Gradle executable is missing: $gradle")
        val command = listOf(
            "sh",
            gradle.toString(),
            "--offline",
            "--no-daemon",
            "--stacktrace",
            "-PandroidHardening=true",
        ) + extraArguments + listOf(
            ":mobile:hardeningBundleDemoQa",
            ":mobile:hardeningAssembleDemoQa",
        )
        val gradleUserHome = projectDirectory.resolve("empty-gradle-home")
        val gradleUserHomeExistedBeforeLaunch = Files.exists(gradleUserHome)
        val process = ProcessBuilder(command)
            .directory(projectDirectory.toFile())
            .redirectErrorStream(true)
        process.environment().remove("GRADLE_RO_DEP_CACHE")
        process.environment()["GRADLE_USER_HOME"] = gradleUserHome.toString()
        val running = process.start()
        val output = running.inputStream.bufferedReader().readText()
        return ConsumerResult(
            running.waitFor(),
            output,
            command,
            gradleUserHome,
            gradleUserHomeExistedBeforeLaunch,
        )
    }

    private fun hardeningArtifactHashes(): Map<String, String> {
        val mobile = projectDirectory.resolve("mobile")
        val roots = listOf(
            mobile.resolve("build/outputs/bundle/demoQa"),
            mobile.resolve("build/outputs/hardening/demoQa"),
            mobile.resolve("build/reports/hardening/demoQa"),
        )
        val hardeningWork = mobile.resolve("build/hardening/demoQa")
        val stableWorkArtifacts = Files.walk(hardeningWork).use { paths ->
            paths.filter(Files::isRegularFile)
                .filter { path -> path.fileName.toString() in setOf("applymapping.pro", "registry.json") }
                .sorted()
                .toList()
        }
        assertEquals(
            setOf("applymapping.pro", "registry.json"),
            stableWorkArtifacts.mapTo(linkedSetOf()) { path -> path.fileName.toString() },
        )
        val artifacts = listOf(
            mobile.resolve("build/outputs/mapping/demoQa/mapping.txt"),
        ) + stableWorkArtifacts + roots.flatMap { root ->
            assertTrue(Files.isDirectory(root), "consumer artifact directory is missing: $root")
            Files.walk(root).use { paths ->
                paths.filter(Files::isRegularFile).sorted().toList()
            }
        }
        assertTrue(artifacts.isNotEmpty(), "consumer produced no hardening artifacts")
        return artifacts.associate { artifact ->
            val identity = if (artifact in stableWorkArtifacts) {
                "build/hardening/demoQa/${artifact.fileName}"
            } else {
                mobile.relativize(artifact).toString().replace('\\', '/')
            }
            identity to sha256(artifact)
        }.toSortedMap()
    }

    private fun hardeningRegistrySnapshot(): RegistrySnapshot {
        val hardeningWork = projectDirectory.resolve("mobile/build/hardening/demoQa")
        val registry = Files.walk(hardeningWork).use { paths ->
            paths.filter(Files::isRegularFile)
                .filter { path -> path.fileName.toString() == "registry.json" }
                .toList()
                .single()
        }
        return RegistryCodec().decode(registry.readText())
    }

    private fun hardeningApplyMappingSemantics(): ApplyMappingSemantics {
        val hardeningWork = projectDirectory.resolve("mobile/build/hardening/demoQa")
        val rulesPath = Files.walk(hardeningWork).use { paths ->
            paths.filter(Files::isRegularFile)
                .filter { path -> path.fileName.toString() == "applymapping.pro" }
                .toList()
                .single()
        }
        val rules = rulesPath.readText()
        val matches = APPLY_MAPPING_DIRECTIVE.findAll(rules).toList()
        assertEquals(1, matches.size, "prepared rules must contain exactly one -applymapping directive")
        val match = matches.single()
        val target = Path.of(unescapeProguardPath(match.groupValues[1])).toAbsolutePath().normalize()
        assertTrue(Files.isRegularFile(target), "-applymapping target is missing: $target")
        val preparedBoundary = requireNotNull(rulesPath.parent).toRealPath()
        val realTarget = target.toRealPath()
        assertEquals(
            preparedBoundary.resolve("app-only-previous-mapping.txt"),
            realTarget,
            "-applymapping must reference the app-only mapping inside its prepared boundary",
        )
        val normalizedRules = rules.replaceRange(
            match.range,
            "-applymapping \"<prepared>/app-only-previous-mapping.txt\"",
        )
        val mapping = realTarget.readText()
        return ApplyMappingSemantics(
            normalizedRules,
            sha256(realTarget),
            R8MappingParser().parse(mapping, null).symbols,
        )
    }

    private fun unescapeProguardPath(value: String): String = buildString {
        var escaped = false
        value.forEach { character ->
            if (escaped) {
                require(character == '\\' || character == '"') { "unsupported escaped Proguard path character" }
                append(character)
                escaped = false
            } else if (character == '\\') {
                escaped = true
            } else {
                append(character)
            }
        }
        require(!escaped) { "unterminated escaped Proguard path" }
    }

    private fun cleanConsumerExecution(preserveHardeningState: Boolean) {
        listOf(
            projectDirectory.resolve(".gradle"),
            projectDirectory.resolve("build"),
            projectDirectory.resolve("empty-gradle-home"),
            projectDirectory.resolve("mobile/build"),
            projectDirectory.resolve("core/build"),
            projectDirectory.resolve("media/build"),
        ).forEach(::deleteTree)
        if (!preserveHardeningState) deleteTree(projectDirectory.resolve("mobile/.hardening"))
    }

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private fun verifyConsumerArtifacts(expectedR8Version: String?) {
        val mobile = projectDirectory.resolve("mobile")
        val hardenedAab = mobile.resolve("build/outputs/hardening/demoQa/demoQa-hardened.aab")
        val hardenedApk = mobile.resolve("build/outputs/hardening/demoQa/demoQa-hardened-universal.apk")
        val ordinaryAab = mobile.resolve("build/outputs/bundle/demoQa")
            .listDirectoryEntries("*.aab")
            .single()
        val fullMapping = mobile.resolve("build/outputs/mapping/demoQa/mapping.txt")
        val reports = mobile.resolve("build/reports/hardening/demoQa")
        val mappingReport = reports.resolve("mapping-verification.json")
        val bundleReport = reports.resolve("bundle-verification.json")
        val apkReport = reports.resolve("universal-apk-verification.json")
        val state = mobile.resolve(".hardening/mappings/portable-demo/demoQa")

        listOf(hardenedAab, hardenedApk, ordinaryAab, fullMapping, mappingReport, bundleReport, apkReport)
            .forEach { artifact -> assertTrue(Files.isRegularFile(artifact), "consumer artifact is missing: $artifact") }
        assertDexHeader(hardenedAab, "base/dex/classes.dex")
        assertDexHeader(hardenedApk, "classes.dex")

        val mapping = fullMapping.readText()
        listOf(
            "com.example.owned.MainActivity",
            "com.example.owned.OwnedJava",
            "com.example.owned.OwnedKotlin",
            "com.example.core.CoreOwned",
            "com.example.media.MediaOwned",
        ).forEach { symbol -> assertContains(mapping, symbol) }

        val mappingVerification = mappingReport.readText()
        assertContains(mappingVerification, "\"status\":\"PASS\"")
        if (expectedR8Version == null) {
            assertTrue(
                Regex("""\"r8Version\":\"[0-9]+\.[0-9]+\.[0-9]+\"""").containsMatchIn(mappingVerification),
                mappingVerification,
            )
        } else {
            assertContains(mappingVerification, "\"r8Version\":\"$expectedR8Version\"")
        }
        assertContains(mappingVerification, "\"retraceVerified\":true")
        assertTrue(
            Regex("""com\.example\.[^"]+\.[^"]+\([^\"]+:\d+\)""").containsMatchIn(mappingVerification),
            mappingVerification,
        )
        assertContains(bundleReport.readText(), "\"bundletoolValidated\":true")
        val apkVerification = apkReport.readText()
        assertContains(apkVerification, "\"zipalignVerified\":true")
        assertContains(apkVerification, "\"apkSignatureVerified\":true")

        assertTrue(Files.isRegularFile(state.resolve("current/active.json")), "active hardening state is missing")
        assertTrue(Files.isDirectory(state.resolve("history")), "hardening history is missing")
        val hardeningWork = mobile.resolve("build/hardening/demoQa")
        val workNames = Files.walk(hardeningWork).use { paths ->
            paths.filter(Files::isRegularFile).map { path -> path.fileName.toString() }.toList().toSet()
        }
        listOf("applymapping.pro", "registry.json").forEach { name ->
            assertTrue(name in workNames, "consumer hardening work is missing $name")
        }

        val sdk = Path.of(
            requireNotNull(System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")) {
                "ANDROID_HOME or ANDROID_SDK_ROOT is required"
            },
        )
        val buildTools = sdk.resolve("build-tools/35.0.0")
        val jarsigner = Path.of(System.getProperty("java.home"), "bin", "jarsigner")
        val jarsignerResult = runCommand(
            jarsigner,
            "-J-Duser.language=en",
            "-J-Duser.country=US",
            "-verify",
            "-strict",
            "-verbose",
            "-keystore",
            mobile.resolve("fixture-signing.p12"),
            "-storetype",
            "PKCS12",
            "-storepass",
            "fixture-password",
            hardenedAab.toString(),
        )
        assertEquals(0, jarsignerResult.exitCode, jarsignerResult.output)
        assertContains(jarsignerResult.output.lowercase(), "jar verified")
        assertEquals(0, runCommand(buildTools.resolve("zipalign"), "-c", "-v", "4", hardenedApk.toString()).exitCode)
        val apksignerResult = runCommand(
            buildTools.resolve("apksigner"),
            "verify",
            "--verbose",
            "--print-certs",
            hardenedApk.toString(),
        )
        assertEquals(0, apksignerResult.exitCode, apksignerResult.output)
        assertContains(apksignerResult.output, "Verified")
        val apkVerificationResult = ApkVerifier.Builder(hardenedApk.toFile()).build().verify()
        assertTrue(apkVerificationResult.isVerified, apkVerificationResult.errors.joinToString())
        val apkCertificateSha256 = apkVerificationResult.signerCertificates
            .map { certificate -> sha256(certificate.encoded) }
            .toSet()
            .single()
        assertEquals(aabCertificateSha256(hardenedAab), apkCertificateSha256)
    }

    private fun assertDexHeader(archive: Path, entryName: String) {
        ZipFile(archive.toFile()).use { zip ->
            val entry = requireNotNull(zip.getEntry(entryName)) { "$archive is missing $entryName" }
            val bytes = zip.getInputStream(entry).use(InputStream::readBytes)
            assertTrue(bytes.size >= 112, "$archive has a truncated DEX header")
            assertTrue(
                bytes.copyOfRange(0, 4).contentEquals("dex\n".toByteArray()),
                "$archive has an unreadable DEX header",
            )
            val expectedSignature = MessageDigest.getInstance("SHA-1").digest(bytes.copyOfRange(32, bytes.size))
            assertTrue(
                expectedSignature.contentEquals(bytes.copyOfRange(12, 32)),
                "$archive has an invalid DEX SHA-1 signature",
            )
            val adler32 = Adler32().apply { update(bytes, 12, bytes.size - 12) }.value
            val storedChecksum = (0 until 4).fold(0L) { value, index ->
                value or ((bytes[8 + index].toLong() and 0xffL) shl (index * 8))
            }
            assertEquals(adler32, storedChecksum, "$archive has an invalid DEX Adler32 checksum")
            assertTrue(
                DexBackedDexFile.fromInputStream(null, bytes.inputStream()).classes.iterator().hasNext(),
                "$archive has no parseable DEX classes",
            )
        }
    }

    private fun aabCertificateSha256(bundle: Path): String = JarFile(bundle.toFile(), true).use { jar ->
        jar.entries().asSequence()
            .filterNot { entry -> entry.isDirectory || entry.name.startsWith("META-INF/") }
            .flatMap { entry ->
                jar.getInputStream(entry).use { input -> input.readBytes() }
                entry.certificates.orEmpty().asSequence()
            }
            .map { certificate -> sha256(certificate.encoded) }
            .toSet()
            .single()
    }

    private fun runCommand(vararg command: Any): CommandResult {
        val arguments = command.map(Any::toString)
        val process = ProcessBuilder(arguments).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        return CommandResult(process.waitFor(), output)
    }

    private fun extract(archive: Path, destination: Path) {
        ZipFile(archive.toFile()).use { zip ->
            zip.entries().asSequence().forEach { entry ->
                val output = destination.resolve(entry.name).normalize()
                require(output.startsWith(destination)) { "portable ZIP entry escapes extraction root" }
                if (entry.isDirectory) {
                    output.createDirectories()
                } else {
                    output.parent.createDirectories()
                    zip.getInputStream(entry).use { input ->
                        Files.copy(input, output, REPLACE_EXISTING)
                    }
                }
            }
        }
    }

    private fun extractPortableRepository(offlineExtraction: Path): Path {
        val packaged = offlineExtraction.resolve("portable").listDirectoryEntries("*.zip").single()
        val destination = projectDirectory.resolve("portable-maven")
        extract(packaged, destination)
        val repository = destination.resolve("repository")
        assertTrue(Files.isDirectory(repository), "exact portable ZIP repository is missing")
        val metadata = destination.resolve("verification-metadata.xml")
        assertTrue(Files.isRegularFile(metadata), "exact portable ZIP verification metadata is missing")
        return repository
    }

    private fun mergeRepository(source: Path, destination: Path) {
        Files.walk(source).use { paths ->
            paths.sorted().forEach { path ->
                val target = destination.resolve(source.relativize(path).toString())
                if (Files.isDirectory(path)) {
                    target.createDirectories()
                } else if (Files.isRegularFile(path)) {
                    target.parent.createDirectories()
                    if (Files.exists(target)) {
                        if (target.fileName.toString().endsWith(".pom")) {
                            Files.copy(path, target, REPLACE_EXISTING)
                        } else {
                            assertEquals(sha256(path), sha256(target), "repository merge conflict at $target")
                        }
                    } else {
                        Files.copy(path, target)
                    }
                }
            }
        }
    }

    private companion object {
        const val NEUTRAL_LEGACY_GROUP = "com.holin.fixture"
        const val NEUTRAL_LEGACY_MODULE = "neutral-legacy-plugin"
        const val NEUTRAL_LEGACY_PLUGIN_ID = "com.holin.fixture.legacy"
        const val NEUTRAL_LEGACY_VERSION = "1.0.0"
        val APPLY_MAPPING_DIRECTIVE = Regex("""(?m)^-applymapping "(.*)"$""")

        val PORTABLE_TASKS = listOf(
            "prepareHardeningDemoQa",
            "auditHardeningDemoQa",
            "verifyHardeningDemoQa",
            "archiveHardeningDemoQa",
            "hardeningBundleDemoQa",
            "hardeningAssembleDemoQa",
            "compareHardeningDemoQa",
            "smokeHardeningDemoQa",
            "hardeningRunDemoQa",
        )
    }

    private data class ConsumerResult(
        val exitCode: Int,
        val output: String,
        val command: List<String>,
        val gradleUserHome: Path,
        val gradleUserHomeExistedBeforeLaunch: Boolean,
    )

    private data class ApplyMappingSemantics(
        val normalizedRules: String,
        val targetSha256: String,
        val symbols: Map<MappingSymbolKey, Set<String>>,
    )

    private data class CommandResult(val exitCode: Int, val output: String)
}
