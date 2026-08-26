package com.holin.android.hardening

import com.android.apksig.ApkVerifier
import com.holin.android.hardening.state.PreparedStateCodec
import com.holin.android.hardening.state.SeedDerivationMode
import groovy.json.JsonSlurper
import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.security.KeyStore
import java.util.zip.ZipFile
import javax.imageio.ImageIO
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
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
import org.junit.jupiter.api.io.TempDir

class AgpPublicWiringFunctionalTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `real AGP fixture configures the public hardcoded reference DSL`() {
        writeAndroidFixture()
        Files.writeString(
            projectDirectory.resolve("build.gradle"),
            """

            androidHardening {
                ownership {
                    hardcodedReferences {
                        kinds.set([
                            com.holin.android.hardening.HardcodedReferenceKind.URL,
                            com.holin.android.hardening.HardcodedReferenceKind.FILE_NAME,
                        ])
                        includeGlobs.set(['**/*.java'])
                        excludeGlobs.set(['**/generated/**'])
                        failOnUnresolvedOwnedReference.set(false)
                    }
                }
            }
            tasks.register('inspectHardcodedReferenceDsl') {
                doLast {
                    def hardcoded = androidHardening.ownership.hardcodedReferences
                    println("H2B_KINDS=" + hardcoded.kinds.get().collect { it.name() }.sort())
                    println("H2B_INCLUDES=" + hardcoded.includeGlobs.get())
                    println("H2B_EXCLUDES=" + hardcoded.excludeGlobs.get())
                    println("H2B_FAIL=" + hardcoded.failOnUnresolvedOwnedReference.get())
                }
            }
            """.trimIndent(),
            java.nio.file.StandardOpenOption.APPEND,
        )

        val output = runner("inspectHardcodedReferenceDsl").build().output

        assertContains(output, "H2B_KINDS=[FILE_NAME, URL]")
        assertContains(output, "H2B_INCLUDES=[**/*.java]")
        assertContains(output, "H2B_EXCLUDES=[**/generated/**]")
        assertContains(output, "H2B_FAIL=false")
    }

    @Test
    fun `device acceptance consumes variant application id and merged manifest artifact`() {
        writeAndroidFixture(includeDebug = true)
        Files.writeString(
            projectDirectory.resolve("build.gradle"),
            """

            tasks.register('inspectDeviceAcceptanceInputs') {
                doLast {
                    def smoke = tasks.named('smokeHardeningDemoDebug').get()
                    println("DEVICE_VARIANT_APPLICATION_ID=" + smoke.variantApplicationId.get())
                    println("DEVICE_MERGED_MANIFEST=" + smoke.mergedManifest.get().asFile)
                    println("DEVICE_APPLICATION_ID_FROM_VARIANT=" + smoke.applicationIdFromVariant.get())
                    println("DEVICE_LAUNCH_FROM_MANIFEST=" + smoke.launchActivityFromManifest.get())
                }
            }
            """.trimIndent(),
            java.nio.file.StandardOpenOption.APPEND,
        )

        val output = runner("inspectDeviceAcceptanceInputs").build().output

        assertContains(output, "DEVICE_VARIANT_APPLICATION_ID=com.example.demo.app")
        assertContains(output, "DEVICE_MERGED_MANIFEST=")
        assertContains(output, "AndroidManifest.xml")
        assertContains(output, "DEVICE_APPLICATION_ID_FROM_VARIANT=true")
        assertContains(output, "DEVICE_LAUNCH_FROM_MANIFEST=true")
    }

    @Test
    fun `real AGP exposes the AAPT2 executable through its provider backed SDK component`() {
        writeAndroidFixture()
        Files.writeString(
            projectDirectory.resolve("build.gradle"),
            """

            tasks.register('inspectHardeningAapt2') {
                doLast {
                    def universal = tasks.named('assembleHardeningDemoReleaseUniversalApk').get()
                    println('HARDENING_AAPT2=' + universal.aapt2Executable.get().asFile.absolutePath)
                }
            }
            """.trimIndent(),
            java.nio.file.StandardOpenOption.APPEND,
        )

        val output = runner(
            "-PandroidHardening=true",
            "prepareHardeningDemoRelease",
            "inspectHardeningAapt2",
        ).build().output

        assertContains(output, "HARDENING_AAPT2=")
        assertContains(output, "/aapt2")
    }

    @Test
    fun `selected Android variant supplies public namespace application id and version code`() {
        writeAndroidFixture()

        runner("-PandroidHardening=true", "prepareHardeningDemoRelease").build()

        val prepared = projectDirectory.resolve("build/hardening/demoRelease")
            .listDirectoryEntries("prepared-*")
            .single()
        val manifest = prepared.resolve("manifest.json").readText()
        assertContains(manifest, "\"namespace\":\"com.example.demo\"")
        assertContains(manifest, "\"applicationId\":\"com.example.demo.app\"")
        val handoff = prepared.resolve("prepared-state.properties").readText()
        assertContains(handoff, "generation=1")
        assertFalse(projectDirectory.resolve(".hardening").toFile().exists())
        assertTrue(projectDirectory.resolve("fixture-state/demo/demoRelease/locks/state.lock").toFile().exists())
    }

    @Test
    fun `fixed seed property makes real AGP prepares deterministic without exposing raw seed`() {
        writeFixedSeedAndroidFixture()
        val rawSeed = "fixture fixed seed that must remain secret"
        val arguments = arrayOf(
            "-PandroidHardening=true",
            "-PandroidHardeningSeed=$rawSeed",
            "prepareHardeningDemoRelease",
        )

        runner(*arguments).build()
        runner(*arguments).build()

        val prepared = projectDirectory.resolve("build/hardening/demoRelease")
            .listDirectoryEntries("prepared-*")
            .sortedBy { it.fileName.toString() }
        assertEquals(2, prepared.size)
        assertNotEquals(prepared[0].fileName.toString(), prepared[1].fileName.toString())
        val states = prepared.map { directory ->
            PreparedStateCodec.read(directory.resolve("prepared-state.properties"))
        }
        assertEquals(SeedDerivationMode.FIXED_SEED, states[0].identity.derivationMode)
        assertEquals(states[0].contentSaltSha256, states[1].contentSaltSha256)
        assertEquals(states[0].identity.lineageId, states[1].identity.lineageId)
        assertEquals(states[0].identity.seedHash, states[1].identity.seedHash)
        listOf("manifest.json", "mapping.txt", "registry.json", "seed.bin", "applymapping.pro").forEach { name ->
            assertTrue(
                Files.readAllBytes(prepared[0].resolve(name)).contentEquals(Files.readAllBytes(prepared[1].resolve(name))),
                "$name differs across fixed-seed prepares",
            )
        }
        assertRawSeedAbsent(
            rawSeed,
            listOf(projectDirectory.resolve("build"), projectDirectory.resolve("fixture-state")),
        )
    }

    @Test
    fun `fixed seed derivation binds complete version signing ownership and transform identity`() {
        writeFixedSeedAndroidFixture()
        createFixtureKeyStore("fixture-signing-alternate.p12", "fixture-key", "Alternate Hardening Release TestKit Fixture")
        val rawSeed = "fixture fixed seed bound to complete configuration"
        val arguments = arrayOf(
            "-PandroidHardening=true",
            "-PandroidHardeningSeed=$rawSeed",
            "prepareHardeningDemoRelease",
        )
        val buildFile = projectDirectory.resolve("build.gradle")
        val baselineScript = buildFile.readText()
        val preparedRoot = projectDirectory.resolve("build/hardening/demoRelease")

        fun derivedSalt(buildScript: String): String {
            buildFile.writeText(buildScript)
            val before = if (preparedRoot.exists()) {
                preparedRoot.listDirectoryEntries("prepared-*").toSet()
            } else {
                emptySet()
            }
            runner(*arguments).build()
            val prepared = (preparedRoot.listDirectoryEntries("prepared-*").toSet() - before).single()
            return PreparedStateCodec.read(prepared.resolve("prepared-state.properties")).contentSaltSha256
        }

        val baselineSalt = derivedSalt(baselineScript)
        val variants = linkedMapOf(
            "version" to baselineScript.replace("versionName = '1.0'", "versionName = '1.1'"),
            "signing" to baselineScript.replace("file('fixture-signing.p12')", "file('fixture-signing-alternate.p12')"),
            "ownership" to baselineScript.replace(
                "module(':') { sourceSets.add('main') }",
                "module(':') { sourceSets.add('main') }\n                    generatedPackagePrefixes.add('com.example.generated')",
            ),
            "transform" to baselineScript.replace(
                "rules {\n                    sourceFiles.from('proguard-rules.pro')",
                "code { diversification { minimumSimHashDistance.set(5) } }\n                rules {\n                    sourceFiles.from('proguard-rules.pro')",
            ),
        )
        variants.forEach { (label, buildScript) ->
            assertNotEquals(baselineScript, buildScript, "$label fixture mutation was not applied")
            assertNotEquals(baselineSalt, derivedSalt(buildScript), "$label did not change fixed-seed derivation")
        }
        buildFile.writeText(baselineScript)
    }

    @Test
    fun `separate real AGP prepares without fixed seed rotate content salt`() {
        writeAndroidFixture()
        val arguments = arrayOf("-PandroidHardening=true", "prepareHardeningDemoRelease")

        runner(*arguments).build()
        runner(*arguments).build()

        val prepared = projectDirectory.resolve("build/hardening/demoRelease")
            .listDirectoryEntries("prepared-*")
            .sortedBy { it.fileName.toString() }
        assertEquals(2, prepared.size)
        val states = prepared.map { directory ->
            PreparedStateCodec.read(directory.resolve("prepared-state.properties"))
        }
        assertTrue(states.all { state -> state.identity.derivationMode == SeedDerivationMode.SECURE_RANDOM })
        assertNotEquals(states[0].contentSaltSha256, states[1].contentSaltSha256)
    }

    @Test
    fun `missing opt in fails before producing any bundle`() {
        writeAndroidFixture()

        val result = runner("hardeningBundleDemoRelease").buildAndFail()

        assertContains(
            result.output,
            "./gradlew -PandroidHardening=true hardeningBundleDemoRelease",
        )
        assertFalse(projectDirectory.resolve("build/outputs").toFile().walkTopDown().any { it.extension == "aab" })
    }

    @Test
    fun `ordinary bundle does not execute or publish hardening`() {
        writeAndroidFixture()

        runner("bundleDemoRelease").build()

        assertTrue(
            projectDirectory.resolve("build/outputs/bundle").toFile()
                .walkTopDown()
                .any { it.isFile && it.extension == "aab" },
        )
        assertFalse(
            projectDirectory.resolve("build/outputs/hardening/demoRelease/demoRelease-hardened.aab")
                .toFile()
                .exists(),
        )
        assertFalse(projectDirectory.resolve("fixture-state").toFile().exists())
    }

    @Test
    fun `ordinary bundle stays ordinary when the hardening property is present`() {
        writeAndroidFixture()

        val result = runner("-PandroidHardening=true", "bundleDemoRelease").build()

        assertFalse(result.output.contains(":prepareHardeningDemoRelease"))
        assertFalse(projectDirectory.resolve("build/outputs/hardening/demoRelease").toFile().exists())
        assertFalse(projectDirectory.resolve("fixture-state").toFile().exists())
        assertContains(
            projectDirectory.resolve("build/outputs/mapping/demoRelease/configuration.txt").readText(),
            "-keep class com.example.demo.match.** { *; }",
        )
    }

    @Test
    fun `enabled hardening entry rewrites validates signs publishes and archives the real bundle`() {
        writeAndroidFixture(maximumOverallExclusive = 100.0)

        runner("-PandroidHardening=true", "hardeningBundleDemoRelease").build()

        val hardened = projectDirectory.resolve(
            "build/outputs/hardening/demoRelease/demoRelease-hardened.aab",
        )
        assertTrue(hardened.toFile().isFile)
        val ordinary = projectDirectory.resolve("build/outputs/bundle")
            .toFile()
            .walkTopDown()
            .single { it.isFile && it.extension == "aab" }
            .toPath()
        val ordinaryHash = sha256(ordinary)
        ZipFile(hardened.toFile()).use { archive ->
            assertFalse(
                archive.entries().asSequence().any { entry ->
                    entry.name.startsWith("BUNDLE-METADATA/com.holin.android.hardening/")
                },
            )
        }
        val invocation = projectDirectory.resolve("build/hardening/demoRelease/invocations")
            .listDirectoryEntries()
            .single()
        val rewriteManifest = invocation.resolve("rewrite-manifest.json").readText()
        assertContains(rewriteManifest, "\"originalAabSha256\":\"$ordinaryHash\"")
        val semanticResults = invocation.resolve("semantic-results.json").readText()
        assertContains(semanticResults, "\"schemaVersion\":1")
        val transformation = invocation.resolve("transformation-report.json").readText()
        assertContains(
            transformation,
            "\"ownedModules\":[\":\"]",
        )
        assertContains(transformation, "\"transformedDexCount\":1")
        assertContains(transformation, "\"renamedResourceCount\":1")
        val mappingVerification = invocation.resolve("mapping-verification.json").readText()
        assertContains(mappingVerification, "\"status\":\"PASS\"")
        assertContains(mappingVerification, "\"r8Version\":\"8.13.19\"")
        assertContains(mappingVerification, "\"retraceVerified\":true")
        val r8Configuration = projectDirectory.resolve(
            "build/outputs/mapping/demoRelease/configuration.txt",
        ).readText()
        assertContains(
            r8Configuration,
            "-keep,allowobfuscation,allowshrinking class com.example.demo.match.MainActivity { *; }",
        )
        assertFalse(
            r8Configuration.contains(
                "-keep,allowobfuscation,allowshrinking class com.example.demo.match.** { *; }",
            ),
        )
        val publishedMappingVerification = projectDirectory.resolve(
            "build/reports/hardening/demoRelease/mapping-verification.json",
        ).readText()
        assertEquals(mappingVerification, publishedMappingVerification)
        val report = projectDirectory.resolve(
            "build/reports/hardening/demoRelease/bundle-verification.json",
        ).readText()
        assertContains(report, "\"bundletoolValidated\":true")
        val hardenedHash = sha256(hardened)
        assertContains(report, "\"hardenedAabSha256\":\"$hardenedHash\"")
        val history = projectDirectory.resolve("fixture-state/demo/demoRelease/history")
            .listDirectoryEntries()
            .single()
        assertEquals("42-$hardenedHash", history.fileName.toString())
    }

    @Test
    fun `reused lineage applies only the app owned R8 mapping`() {
        writeAndroidFixture(maximumOverallExclusive = 100.0)

        runner("-PandroidHardening=true", "hardeningBundleDemoRelease").build()
        runner("-PandroidHardening=true", "prepareHardeningDemoRelease").build()

        val reused = projectDirectory.resolve("build/hardening/demoRelease")
            .listDirectoryEntries("prepared-*")
            .single { prepared ->
                prepared.resolve("prepared-state.properties").readText().contains("reason=REUSED_CURRENT")
            }
        val fullMapping = reused.resolve("mapping.txt")
        val appOnlyMapping = reused.resolve("app-only-previous-mapping.txt")
        val applyMappingRules = reused.resolve("applymapping.pro").readText()

        assertTrue(Files.size(fullMapping) > Files.size(appOnlyMapping))
        assertContains(fullMapping.readText(), "# compiler: R8")
        assertFalse(appOnlyMapping.readText().contains("# compiler: R8"))
        assertContains(applyMappingRules, appOnlyMapping.toAbsolutePath().normalize().toString())
        assertFalse(applyMappingRules.contains(fullMapping.toAbsolutePath().normalize().toString()))
    }

    @Test
    fun `enabled assemble builds a signed universal APK from the verified hardened bundle`() {
        writeAndroidFixture(maximumOverallExclusive = 100.0)
        Files.writeString(
            projectDirectory.resolve("build.gradle"),
            """

            tasks.configureEach {
                if (name == 'assembleHardeningDemoReleaseUniversalApk') doFirst { task ->
                    def manifestInput = task.rewriteManifest.get().asFile
                    def zipalignInput = task.zipalignExecutable.get().asFile
                    assert manifestInput.name == 'rewrite-manifest.json'
                    assert zipalignInput.parentFile.parentFile.name == 'build-tools'
                    assert zipalignInput.name == (System.getProperty('os.name').toLowerCase().contains('win') ? 'zipalign.exe' : 'zipalign')
                    def dependencyNames = task.taskDependencies.getDependencies(task)*.name
                    assert !dependencyNames.any { it.toLowerCase().contains('upload') || it.toLowerCase().contains('publish') || it.toLowerCase().contains('showcase') }
                    file('universal-inputs.txt').text = manifestInput.absolutePath + '\n' + zipalignInput.absolutePath
                }
            }
            """.trimIndent(),
            java.nio.file.StandardOpenOption.APPEND,
        )

        runner("-PandroidHardening=true", "hardeningAssembleDemoRelease").build()

        val hardenedBundle = projectDirectory.resolve(
            "build/outputs/hardening/demoRelease/demoRelease-hardened.aab",
        )
        val universalApk = projectDirectory.resolve(
            "build/outputs/hardening/demoRelease/demoRelease-hardened-universal.apk",
        )
        val bundleReport = projectDirectory.resolve(
            "build/reports/hardening/demoRelease/bundle-verification.json",
        ).readText()
        val apkReport = projectDirectory.resolve(
            "build/reports/hardening/demoRelease/universal-apk-verification.json",
        ).readText()

        assertTrue(hardenedBundle.toFile().isFile)
        assertTrue(universalApk.toFile().isFile)
        FORBIDDEN_SENTINEL_MARKERS.forEach { marker ->
            assertFalse(projectDirectory.resolve(marker).toFile().exists(), "forbidden sentinel executed: $marker")
        }
        val result = ApkVerifier.Builder(universalApk.toFile()).build().verify()
        assertTrue(result.isVerified, result.errors.joinToString())
        val signerHashes = result.signerCertificates
            .map { certificate -> sha256(certificate.encoded) }
            .toSet()
        assertEquals(1, signerHashes.size)
        val signerHash = signerHashes.single()
        assertContains(bundleReport, "\"signerCertificateSha256\":\"$signerHash\"")
        assertContains(apkReport, "\"hardenedAabSha256\":\"${sha256(hardenedBundle)}\"")
        assertContains(apkReport, "\"universalApkSha256\":\"${sha256(universalApk)}\"")
        assertContains(apkReport, "\"signerCertificateSha256\":\"$signerHash\"")
        assertContains(apkReport, "\"bundletoolVersion\":\"1.18.1\"")
        assertContains(apkReport, "\"binaryXmlDiversifiedCount\":1")
        assertContains(apkReport, "\"zipalignVerified\":true")
        assertContains(apkReport, "\"apkSignatureVerified\":true")
        val universalInputs = projectDirectory.resolve("universal-inputs.txt").readText()
        assertContains(universalInputs, "rewrite-manifest.json")
        assertContains(universalInputs, "/build-tools/")
    }

    @Test
    fun `fixed seed makes repeated real AGP assembles byte identical without leaking raw seed`() {
        writeFixedSeedAndroidFixture()
        val rawSeed = "fixture fixed seed that must remain secret"
        projectDirectory.resolve("src/main/java/com/example/demo/match/MainActivity.java").writeText(
            """
            package com.example.demo.match;

            import android.app.Activity;
            import android.os.Bundle;
            import com.example.owned.FixtureOwned;
            import com.example.demo.R;

            public final class MainActivity extends Activity {
                @Override public void onCreate(Bundle state) {
                    super.onCreate(state);
                    setContentView(R.layout.activity_main);
                    setTitle(Integer.toString(new FixtureOwned().size()));
                }
            }
            """.trimIndent(),
        )
        val arguments = arrayOf(
            "-PandroidHardening=true",
            "-PandroidHardeningSeed=$rawSeed",
            "hardeningAssembleDemoRelease",
        )
        val invocationRoot = projectDirectory.resolve("build/hardening/demoRelease/invocations")

        runner(*arguments).build()
        val firstBuildInvocations = invocationRoot.listDirectoryEntries().toSet()
        val firstBuildInvocation = firstBuildInvocations.single()
        val hardenedAab = projectDirectory.resolve(
            "build/outputs/hardening/demoRelease/demoRelease-hardened.aab",
        )
        val universalApk = projectDirectory.resolve(
            "build/outputs/hardening/demoRelease/demoRelease-hardened-universal.apk",
        )
        val r8Mapping = projectDirectory.resolve("build/outputs/mapping/demoRelease/mapping.txt")
        val publicReports = projectDirectory.resolve("build/reports/hardening/demoRelease")
        val stateRoot = projectDirectory.resolve("fixture-state/demo/demoRelease")
        val activePointer = stateRoot.resolve("current/active.json")
        val firstAabBytes = Files.readAllBytes(hardenedAab)
        val firstApkBytes = Files.readAllBytes(universalApk)
        val firstMappingBytes = Files.readAllBytes(r8Mapping)
        val firstReportFingerprint = stateFingerprint(publicReports)
        val firstActiveBytes = Files.readAllBytes(activePointer)
        val firstCurrentFingerprint = stateFingerprint(stateRoot.resolve("current"))
        val firstHistoryFingerprint = stateFingerprint(stateRoot.resolve("history"))
        val firstInvocationFingerprint = stateFingerprint(firstBuildInvocation)

        runner(*arguments).build()
        val secondBuildInvocations = invocationRoot.listDirectoryEntries().toSet()
        val secondBuildInvocation = (secondBuildInvocations - firstBuildInvocations).single()

        assertNotEquals(firstBuildInvocation.fileName.toString(), secondBuildInvocation.fileName.toString())
        assertTrue(firstAabBytes.contentEquals(Files.readAllBytes(hardenedAab)), "hardened AAB bytes differ")
        assertTrue(firstApkBytes.contentEquals(Files.readAllBytes(universalApk)), "universal APK bytes differ")
        assertTrue(firstMappingBytes.contentEquals(Files.readAllBytes(r8Mapping)), "R8 mapping bytes differ")
        assertEquals(firstReportFingerprint, stateFingerprint(publicReports))
        assertTrue(firstActiveBytes.contentEquals(Files.readAllBytes(activePointer)), "active pointer bytes differ")
        assertEquals(firstCurrentFingerprint, stateFingerprint(stateRoot.resolve("current")))
        assertEquals(firstHistoryFingerprint, stateFingerprint(stateRoot.resolve("history")))
        assertEquals(firstInvocationFingerprint, stateFingerprint(secondBuildInvocation))
        val expectedFixedSeedHash = sha256(rawSeed.toByteArray())
        listOf(
            secondBuildInvocation.resolve("transformation-report.json"),
            publicReports.resolve("bundle-verification.json"),
            publicReports.resolve("mapping-verification.json"),
        ).forEach { reportPath ->
            val report = reportPath.readText()
            assertContains(report, "\"fixedSeedProvided\":true")
            assertContains(report, "\"fixedSeedHash\":\"$expectedFixedSeedHash\"")
        }

        val firstGeneration = jsonInt(jsonObject(activePointer.readText()), "generation")
        val fixtureOwned = projectDirectory.resolve("src/main/java/com/example/owned/FixtureOwned.java")
        fixtureOwned.writeText(
            "package com.example.owned; public final class FixtureOwned { public int size() { return 2; } }\n",
        )

        runner(*arguments).build()
        val changedBuildInvocations = invocationRoot.listDirectoryEntries().toSet()
        val changedBuildInvocation = (changedBuildInvocations - secondBuildInvocations).single()
        val changedAabBytes = Files.readAllBytes(hardenedAab)
        val changedTransformationBytes = Files.readAllBytes(
            changedBuildInvocation.resolve("transformation-report.json"),
        )
        val changedMappingReportBytes = Files.readAllBytes(
            publicReports.resolve("mapping-verification.json"),
        )
        val changedReportFingerprint = stateFingerprint(publicReports)
        val changedGeneration = jsonInt(jsonObject(activePointer.readText()), "generation")

        assertFalse(firstAabBytes.contentEquals(changedAabBytes), "changed source did not change the hardened AAB")
        assertEquals(firstGeneration + 1, changedGeneration)

        runner(*arguments).build()
        val repeatedChangedBuildInvocations = invocationRoot.listDirectoryEntries().toSet()
        val repeatedChangedBuildInvocation = (repeatedChangedBuildInvocations - changedBuildInvocations).single()
        val repeatedChangedTransformation = repeatedChangedBuildInvocation.resolve("transformation-report.json")

        assertTrue(changedAabBytes.contentEquals(Files.readAllBytes(hardenedAab)), "changed hardened AAB bytes differ")
        assertTrue(
            changedTransformationBytes.contentEquals(Files.readAllBytes(repeatedChangedTransformation)),
            "changed transformation report bytes differ",
        )
        assertTrue(
            changedMappingReportBytes.contentEquals(
                Files.readAllBytes(publicReports.resolve("mapping-verification.json")),
            ),
            "changed mapping verification report bytes differ",
        )
        assertEquals(changedReportFingerprint, stateFingerprint(publicReports))
        assertEquals(changedGeneration, jsonInt(jsonObject(activePointer.readText()), "generation"))
        assertEquals(
            changedGeneration,
            jsonInt(jsonObject(repeatedChangedTransformation.readText()), "generation"),
        )
        assertRawSeedAbsent(
            rawSeed,
            listOf(projectDirectory.resolve("build"), projectDirectory.resolve("fixture-state")),
        )
    }

    @Test
    fun `separate full assembles without fixed seed preserve naming while rotating hardened artifacts`() {
        writeAndroidFixture(100.0)
        val arguments = arrayOf("-PandroidHardening=true", "hardeningAssembleDemoRelease")
        val hardenedAab = projectDirectory.resolve(
            "build/outputs/hardening/demoRelease/demoRelease-hardened.aab",
        )
        val universalApk = projectDirectory.resolve(
            "build/outputs/hardening/demoRelease/demoRelease-hardened-universal.apk",
        )
        val r8Mapping = projectDirectory.resolve("build/outputs/mapping/demoRelease/mapping.txt")
        val codeNaming = projectDirectory.resolve("build/reports/hardening/demoRelease/code-naming.json")
        val bundleReport = projectDirectory.resolve("build/reports/hardening/demoRelease/bundle-verification.json")
        val mappingReport = projectDirectory.resolve("build/reports/hardening/demoRelease/mapping-verification.json")
        val invocationRoot = projectDirectory.resolve("build/hardening/demoRelease/invocations")

        runner(*arguments).build()
        val firstInvocations = invocationRoot.listDirectoryEntries().toSet()
        val firstInvocation = firstInvocations.single()
        val firstMapping = Files.readAllBytes(r8Mapping)
        val firstNaming = jsonObject(codeNaming.readText())
        val firstResourceRenames = requireNotNull(
            jsonObject(jsonObject(firstInvocation.resolve("transformation-report.json").readText()), "resources")["renames"]
                as? List<*>,
        ) { "first transformation report has no resource renames" }
        val firstContentSalt = jsonString(jsonObject(bundleReport.readText()), "contentSaltSha256")
        val firstAabSha256 = sha256(hardenedAab)
        val firstApkSha256 = sha256(universalApk)

        runner(*arguments).build()
        val secondInvocations = invocationRoot.listDirectoryEntries().toSet()
        val secondInvocation = (secondInvocations - firstInvocations).single()
        val secondNaming = jsonObject(codeNaming.readText())
        val secondResourceRenames = requireNotNull(
            jsonObject(jsonObject(secondInvocation.resolve("transformation-report.json").readText()), "resources")["renames"]
                as? List<*>,
        ) { "second transformation report has no resource renames" }

        assertTrue(firstMapping.contentEquals(Files.readAllBytes(r8Mapping)), "R8 mapping rotated without a source change")
        assertEquals(firstNaming["expectedSymbols"], secondNaming["expectedSymbols"])
        assertEquals(firstNaming["exclusions"], secondNaming["exclusions"])
        assertTrue(firstResourceRenames.isNotEmpty(), "no-seed transformation reported no resource rename assignments")
        assertEquals(firstResourceRenames, secondResourceRenames)
        assertNotEquals(
            firstContentSalt,
            jsonString(jsonObject(bundleReport.readText()), "contentSaltSha256"),
            "no-seed content salt did not rotate",
        )
        assertNotEquals(firstAabSha256, sha256(hardenedAab), "no-seed hardened AAB did not rotate")
        assertNotEquals(firstApkSha256, sha256(universalApk), "no-seed universal APK did not rotate")
        val reproducibilityReports = secondInvocations
            .map { invocation -> invocation.resolve("transformation-report.json") } + listOf(bundleReport, mappingReport)
        reproducibilityReports.forEach { reportPath ->
            assertContains(reportPath.readText(), "\"fixedSeedProvided\":false,\"fixedSeedHash\":null")
        }
    }

    @Test
    fun `complete lifecycle rejects transitive forbidden task contamination before sentinel execution`() {
        writeAndroidFixture(maximumOverallExclusive = 100.0, includeOwnedModules = true)
        Files.writeString(
            projectDirectory.resolve("core/build.gradle"),
            """

            tasks.register('showcaseReleaseSentinel') {
                doLast {
                    rootProject.file('showcase-sentinel-executed.txt').text = 'executed'
                    throw new GradleException('showcase sentinel executed')
                }
            }
            tasks.register('uploadHardeningSentinel') {
                doLast {
                    rootProject.file('upload-sentinel-executed.txt').text = 'executed'
                    throw new GradleException('upload sentinel executed')
                }
            }
            tasks.register('publishHardeningSentinel') {
                doLast {
                    rootProject.file('publish-sentinel-executed.txt').text = 'executed'
                    throw new GradleException('publish sentinel executed')
                }
            }
            tasks.register('installHardeningSentinel') {
                doLast {
                    rootProject.file('install-sentinel-executed.txt').text = 'executed'
                    throw new GradleException('install sentinel executed')
                }
            }
            tasks.register('notifyHardeningSentinel') {
                doLast {
                    rootProject.file('notify-sentinel-executed.txt').text = 'executed'
                    throw new GradleException('notify sentinel executed')
                }
            }
            """.trimIndent(),
            java.nio.file.StandardOpenOption.APPEND,
        )
        Files.writeString(
            projectDirectory.resolve("app/build.gradle"),
            """

            tasks.register('transitiveForbiddenBridge') {
                dependsOn project(':core').tasks.named('showcaseReleaseSentinel')
                dependsOn project(':core').tasks.named('uploadHardeningSentinel')
                dependsOn project(':core').tasks.named('publishHardeningSentinel')
                dependsOn project(':core').tasks.named('installHardeningSentinel')
                dependsOn project(':core').tasks.named('notifyHardeningSentinel')
            }
            tasks.configureEach {
                if (name == 'hardeningAssembleDemoRelease') {
                    dependsOn tasks.named('transitiveForbiddenBridge')
                }
            }
            """.trimIndent(),
            java.nio.file.StandardOpenOption.APPEND,
        )

        val result = runner("-PandroidHardening=true", "hardeningAssembleDemoRelease").buildAndFail()

        assertContains(result.output, "forbidden task graph contamination")
        FORBIDDEN_SENTINEL_MARKERS.forEach { marker ->
            assertFalse(projectDirectory.resolve(marker).toFile().exists(), "forbidden sentinel executed: $marker")
        }
    }

    @Test
    fun `enabled debug assemble turns on R8 and publishes a debug signed hardened APK`() {
        writeAndroidFixture(
            maximumOverallExclusive = 100.0,
            includeDebug = true,
            includeOwnedModules = true,
        )

        val result = runner("-PandroidHardening=true", "hardeningAssembleDemoDebug").build()

        assertContains(result.output, ":minifyDemoDebugWithR8")
        val appBuild = projectDirectory.resolve("app/build")
        val generatedBuildConfig = appBuild.resolve("generated/source/buildConfig")
            .toFile()
            .walkTopDown()
            .single { file -> file.isFile && file.name == "BuildConfig.java" }
            .readText()
        assertContains(generatedBuildConfig, "public static final boolean DEBUG = Boolean.parseBoolean(\"true\");")
        val hardenedBundle = appBuild.resolve("outputs/hardening/demoDebug/demoDebug-hardened.aab")
        val universalApk = appBuild.resolve(
            "outputs/hardening/demoDebug/demoDebug-hardened-universal.apk",
        )
        assertTrue(hardenedBundle.toFile().isFile)
        assertTrue(universalApk.toFile().isFile)
        val verification = ApkVerifier.Builder(universalApk.toFile()).build().verify()
        assertTrue(verification.isVerified, verification.errors.joinToString())
        val debugCertificateSha256 = certificateSha256(
            projectDirectory.resolve("fixture-debug-signing.p12"),
            "fixture-debug-key",
        )
        assertEquals(
            debugCertificateSha256,
            verification.signerCertificates.single().let { certificate -> sha256(certificate.encoded) },
        )
        assertContains(
            appBuild.resolve("reports/hardening/demoDebug/bundle-verification.json").readText(),
            "\"signerCertificateSha256\":\"$debugCertificateSha256\"",
        )
        val codeMapping = appBuild.resolve(
            "intermediates/hardening/demoDebug/code-naming/code-mapping.txt",
        )
        val codeNamingManifest = appBuild.resolve("reports/hardening/demoDebug/code-naming.json").readText()
        val mappingVerification = appBuild.resolve(
            "reports/hardening/demoDebug/mapping-verification.json",
        ).readText()
        val codeNaming = jsonObject(codeNamingManifest)
        val mappingReport = jsonObject(mappingVerification)
        val continuity = jsonObject(mappingReport, "continuity")
        assertContains(mappingVerification, "\"status\":\"PASS\"")
        assertContains(mappingVerification, "\"mismatches\":[]")
        assertTrue(jsonInt(continuity, "noLongerPresentCount") > 0)
        assertContains(codeNamingManifest, "\"expectedSymbols\":[{")
        assertEquals(sha256(codeMapping), jsonString(codeNaming, "mappingSha256"))
        assertEquals(
            jsonString(codeNaming, "mappingSha256"),
            jsonString(mappingReport, "previousMappingSha256"),
        )
        assertEquals(
            jsonString(mappingReport, "currentMappingSha256"),
            jsonString(mappingReport, "preparedMappingSha256"),
        )
        assertTrue(
            projectDirectory.resolve("fixture-state/demo/demoDebug/history")
                .listDirectoryEntries()
                .isNotEmpty(),
        )
        assertFalse(projectDirectory.resolve("fixture-state/demo/demoRelease/history").toFile().exists())
    }

    @Test
    fun `enabled debug assemble failure leaves debug current release state history and APK publication unchanged`() {
        writeAndroidFixture(
            maximumOverallExclusive = 100.0,
            includeDebug = true,
            includeOwnedModules = true,
        )
        runner("-PandroidHardening=true", "hardeningAssembleDemoRelease").build()
        runner("-PandroidHardening=true", "hardeningAssembleDemoDebug").build()

        val debugRoot = projectDirectory.resolve("fixture-state/demo/demoDebug")
        val releaseRoot = projectDirectory.resolve("fixture-state/demo/demoRelease")
        val debugHistory = debugRoot.resolve("history")
        val outputApk = projectDirectory.resolve(
            "app/build/outputs/hardening/demoDebug/demoDebug-hardened-universal.apk",
        )
        val beforeDebug = debugRoot.resolve("current/active.json").readText()
        val beforeRelease = stateFingerprint(releaseRoot)
        val beforeHistory = debugHistory.listDirectoryEntries().map { it.fileName.toString() }.sorted()
        Files.delete(outputApk)
        val source = projectDirectory.resolve("app/src/main/java/com/example/demo/match/MainActivity.java")
        val original = source.readText()
        val closingBrace = original.lastIndexOf('}')
        require(closingBrace >= 0)
        source.writeText(
            original.substring(0, closingBrace) +
                "    public Class<?> loadDynamic(String name) throws ClassNotFoundException { return Class.forName(name); }\n" +
                "}\n",
        )

        val result = runner("-PandroidHardening=true", "hardeningAssembleDemoDebug").buildAndFail()

        assertContains(result.output, "unresolved app reflection")
        assertEquals(beforeDebug, debugRoot.resolve("current/active.json").readText())
        assertEquals(beforeRelease, stateFingerprint(releaseRoot))
        assertEquals(beforeHistory, debugHistory.listDirectoryEntries().map { it.fileName.toString() }.sorted())
        assertFalse(outputApk.toFile().exists())
    }

    @Test
    fun `debug verification fails closed when the code naming manifest input is absent`() {
        writeAndroidFixture(includeDebug = true, includeOwnedModules = true)
        projectDirectory.resolve("app/build.gradle").toFile().appendText(
            """

            tasks.register(
                'verifyMissingDebugCodeNamingManifest',
                com.holin.android.hardening.tasks.VerifyHardeningTask
            ) {
                variantName.set('demoDebug')
                namespace.set('com.example.demo')
                mappingVerificationReport.set(layout.buildDirectory.file('reports/missing-code-naming.json'))
            }
            """.trimIndent(),
        )

        val result = runner(":app:verifyMissingDebugCodeNamingManifest").buildAndFail()

        assertContains(result.output, "hardening verification requires a code naming manifest")
    }

    @Test
    fun `debug verification rejects a tampered code naming manifest`() {
        writeAndroidFixture(includeDebug = true, includeOwnedModules = true)
        val fixtureDirectory = projectDirectory.resolve("app/manifest-verification-fixture").also(Path::createDirectories)
        fixtureDirectory.resolve("placeholder.txt").writeText("placeholder\n")
        fixtureDirectory.resolve("tampered-code-naming.json").writeText(
            """
            {"schemaVersion":1,"variant":"demoDebug","generation":1,"ownedModules":[":app",":core",":compress",":selector",":ucrop"],"mappingSha256":"${"a".repeat(64)}","registrySha256":"${"b".repeat(64)}","expectedSymbols":[{"kind":"CLASS","owner":"com/example/Owner","name":"Owner","descriptor":"Lcom/example/Owner;","alias":"QuietMeadow","outputOwner":"renamed/QuietMeadow"}],"exclusions":[]}
            """.trimIndent(),
        )
        fixtureDirectory.resolve("valid-potential-bean-fields.json").writeText(
            """
            {"schemaVersion":1,"policyVersion":1,"variant":"demoDebug","generation":1,"configurationSha256":"${"c".repeat(64)}","inventorySha256":"${sha256("[]".toByteArray())}","ownedModules":[":app",":core",":compress",":selector",":ucrop"],"fields":[],"retiredLegacyFieldAssignmentCount":0}
            """.trimIndent(),
        )
        projectDirectory.resolve("app/build.gradle").toFile().appendText(
            """

            tasks.register(
                'verifyTamperedDebugCodeNamingManifest',
                com.holin.android.hardening.tasks.VerifyHardeningTask
            ) {
                variantName.set('demoDebug')
                namespace.set('com.example.demo')
                repositoryRoot.set(rootProject.layout.projectDirectory)
                ownership.set(
                    tasks.named('verifyHardeningDemoDebug').flatMap { task -> task.ownership }
                )
                artifactBoundary.set(layout.projectDirectory)
                def placeholder = layout.projectDirectory.file('manifest-verification-fixture/placeholder.txt')
                previousAppOnlyMapping.set(placeholder)
                codeNamingManifest.set(
                    layout.projectDirectory.file('manifest-verification-fixture/tampered-code-naming.json')
                )
                potentialBeanFieldsManifest.set(
                    layout.projectDirectory.file('manifest-verification-fixture/valid-potential-bean-fields.json')
                )
                currentR8Mapping.set(placeholder)
                preparedR8Mapping.set(placeholder)
                hardenedBundle.set(placeholder)
                transformationReport.set(placeholder)
                bundleVerificationReport.set(placeholder)
                mappingVerificationReport.set(layout.buildDirectory.file('reports/tampered-code-naming.json'))
            }
            """.trimIndent(),
        )

        val result = runner(":app:verifyTamperedDebugCodeNamingManifest").buildAndFail()

        assertContains(result.output, "code naming mapping hash mismatch")
    }

    @Test
    fun `ordinary debug assemble stays non minified even when the property is present`() {
        writeAndroidFixture(includeDebug = true)

        val result = runner("-PandroidHardening=true", "assembleDemoDebug").build()

        assertFalse(result.output.contains(":minifyDemoDebugWithR8"))
        assertFalse(projectDirectory.resolve("build/outputs/hardening/demoDebug").toFile().exists())
        assertFalse(projectDirectory.resolve("fixture-state").toFile().exists())
    }

    @Test
    fun `relative similarity failure keeps detached report without publishing candidate state`() {
        writeAndroidFixture(
            includeDebug = true,
            includeOwnedModules = true,
            includeOwnedResources = false,
            minimumImprovementPoints = 100.0,
        )
        runner("-PandroidHardening=true", "captureHardeningBaselineDemoDebug").build()
        val appBuild = projectDirectory.resolve("app/build")
        val publishedBundle = appBuild.resolve(
            "outputs/hardening/demoDebug/demoDebug-hardened.aab",
        )
        val stateRoot = projectDirectory.resolve("fixture-state/demo/demoDebug")
        val historyBefore = stateRoot.resolve("history").listDirectoryEntries()
            .map { entry -> entry.fileName.toString() }
            .sorted()
        val activeBefore = stateRoot.resolve("current/active.json").readText()
        val publishedBundleSha256Before = sha256(publishedBundle)

        val result = runner("-PandroidHardening=true", "compareHardeningDemoDebug").buildAndFail()

        assertContains(result.output, "owned artifact similarity must improve every dimension")
        val similarity = appBuild.resolve("reports/hardening/demoDebug/similarity-report.json")
        assertTrue(similarity.toFile().isFile)
        assertContains(similarity.readText(), "\"scorerVersion\":\"owned-artifact-v1\"")
        assertEquals(publishedBundleSha256Before, sha256(publishedBundle))
        assertEquals(activeBefore, stateRoot.resolve("current/active.json").readText())
        assertEquals(
            historyBefore,
            stateRoot.resolve("history").listDirectoryEntries().map { entry -> entry.fileName.toString() }.sorted(),
        )
        assertFalse(projectDirectory.resolve("fixture-state/demo/demoRelease/history").toFile().exists())
        assertTrue(historyBefore.isNotEmpty())
    }

    @Test
    fun `debug similarity baseline captures immutable dual artifact evidence`() {
        writeAndroidFixture(includeDebug = true, includeOwnedModules = true, includeOwnedResources = false)

        runner("-PandroidHardening=true", "captureHardeningBaselineDemoDebug").build()

        val invocation = projectDirectory.resolve("app/build/hardening/demoDebug/invocations")
            .listDirectoryEntries()
            .single()
        val identityInventory = invocation.resolve("owned-artifact-inventory.json")
        val analysisInventory = invocation.resolve("owned-artifact-analysis-inventory.json")
        assertTrue(identityInventory.toFile().isFile)
        assertTrue(analysisInventory.toFile().isFile)
        assertFalse(identityInventory == analysisInventory)
        assertEquals(identityInventory.readText(), analysisInventory.readText())
        val baseline = projectDirectory.resolve("fixture-baselines/demo/demoDebug/v1")
        val baselineHashes = baseline.listDirectoryEntries().associate { file ->
            file.fileName.toString() to sha256(file)
        }
        assertEquals(
            setOf("baseline.json", "ordinary.aab", "hardened.aab", "ordinary-universal.apk", "hardened-universal.apk"),
            baselineHashes.keys,
        )
        assertContains(baseline.resolve("baseline.json").readText(), "\"scorerVersion\":\"owned-artifact-v1\"")
        val second = runner("-PandroidHardening=true", "captureHardeningBaselineDemoDebug").buildAndFail()
        assertContains(second.output, "hardening baseline already exists and is immutable")
        assertEquals(
            baselineHashes,
            baseline.listDirectoryEntries().associate { file -> file.fileName.toString() to sha256(file) },
        )
    }

    internal fun writeAndroidFixture(
        maximumOverallExclusive: Double = 75.0,
        includeDebug: Boolean = false,
        includeOwnedModules: Boolean = false,
        includeOwnedResources: Boolean = true,
        minimumImprovementPoints: Double = 0.01,
        configureFixedSeed: Boolean = false,
    ) {
        val sdk = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
        require(!sdk.isNullOrBlank()) { "ANDROID_HOME or ANDROID_SDK_ROOT is required for the AGP TestKit fixture" }
        check(ProcessBuilder("git", "init", "-q", projectDirectory.toString()).start().waitFor() == 0)
        installPinnedLegacyPluginFixture(projectDirectory)
        createFixtureKeyStore("fixture-signing.p12", "fixture-key", "Hardening Release TestKit Fixture")
        createFixtureKeyStore("fixture-debug-signing.p12", "fixture-debug-key", "Hardening Debug TestKit Fixture")
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
            rootProject.name = 'agp-public-hardening-fixture'
            ${if (includeOwnedModules) "include ':app', ':core', ':compress', ':selector', ':ucrop'" else ""}
            """.trimIndent(),
        )
        projectDirectory.resolve("local.properties").writeText("sdk.dir=${sdk.replace("\\", "\\\\")}\n")
        val appDirectory = if (includeOwnedModules) projectDirectory.resolve("app") else projectDirectory
        appDirectory.resolve("src/main/java/com/example/demo/match").createDirectories()
        if (includeOwnedResources) {
            appDirectory.resolve("src/main/res/layout").createDirectories()
        } else {
            val drawable = appDirectory.resolve("src/main/res/drawable/fixture_pixel.png")
            drawable.parent.createDirectories()
            check(ImageIO.write(BufferedImage(2, 2, BufferedImage.TYPE_INT_ARGB), "png", drawable.toFile()))
        }
        appDirectory.resolve("src/main/AndroidManifest.xml").writeText(
            """
            <manifest xmlns:android="http://schemas.android.com/apk/res/android">
                <application>
                    <activity
                        android:name="com.example.demo.match.MainActivity"
                        android:exported="true">
                        <intent-filter>
                            <action android:name="android.intent.action.MAIN" />
                            <category android:name="android.intent.category.LAUNCHER" />
                        </intent-filter>
                    </activity>
                </application>
            </manifest>
            """.trimIndent(),
        )
        val activitySource = appDirectory.resolve("src/main/java/com/example/demo/match/MainActivity.java")
        activitySource.writeText(
            if (includeOwnedResources) {
                """
                package com.example.demo.match;

                import android.app.Activity;
                import android.os.Bundle;
                import com.example.demo.R;

                public final class MainActivity extends Activity {
                    @Override public void onCreate(Bundle state) {
                        super.onCreate(state);
                        setContentView(R.layout.activity_main);
                    }
                }
                """.trimIndent()
            } else {
                """
                package com.example.demo.match;

                import android.app.Activity;
                import android.os.Bundle;

                public final class MainActivity extends Activity {
                    @Override public void onCreate(Bundle state) {
                        super.onCreate(state);
                    }
                }
                """.trimIndent()
            },
        )
        appDirectory.resolve("src/main/java/com/example/owned/FixtureOwned.java").also { fixture ->
            fixture.parent.createDirectories()
        }.writeText(
            "package com.example.owned; public final class FixtureOwned { public int size() { return 1; } }\n",
        )
        val layoutSource = appDirectory.resolve("src/main/res/layout/activity_main.xml")
        if (includeOwnedResources) {
            layoutSource.writeText(
                "<FrameLayout xmlns:android=\"http://schemas.android.com/apk/res/android\" android:contentDescription=\"&#x1F600;\" android:layout_width=\"match_parent\" android:layout_height=\"match_parent\" />\n",
            )
        }
        if (!includeOwnedModules) {
            val inventoryActivity = projectDirectory.resolve("app/src/main/java/com/example/demo/match/MainActivity.java")
            inventoryActivity.parent.createDirectories()
            Files.copy(activitySource, inventoryActivity)
            if (includeOwnedResources) {
                val inventoryLayout = projectDirectory.resolve("app/src/main/res/layout/activity_main.xml")
                inventoryLayout.parent.createDirectories()
                Files.copy(layoutSource, inventoryLayout)
            }
        }
        appDirectory.resolve("proguard-rules.pro").writeText(
            "-keep class com.example.demo.match.** { *; }\n",
        )
        if (includeOwnedModules) {
            projectDirectory.resolve("build.gradle").writeText(
                """
                plugins {
                    id 'com.android.application' version '8.13.2' apply false
                    id 'org.jetbrains.kotlin.android' version '2.3.0' apply false
                    id 'com.android.library' version '8.13.2' apply false
                }
                """.trimIndent(),
            )
        }
        appDirectory.resolve("build.gradle").writeText(
            """
            plugins {
                id 'com.android.application'${if (includeOwnedModules) "" else " version '8.13.2'"}
                id 'org.jetbrains.kotlin.android'${if (includeOwnedModules) "" else " version '2.3.0'"}
                id 'com.holin.android.hardening'
            }

            def androidHardeningRequested = providers.gradleProperty('androidHardening')
                .map { it.toBoolean() }
                .orElse(false)
            def demoHardeningTaskNames = [
                'prepareHardeningDemoRelease',
                'auditHardeningDemoRelease',
                'verifyHardeningDemoRelease',
                'archiveHardeningDemoRelease',
                'hardeningBundleDemoRelease',
                'hardeningAssembleDemoRelease',
                'benchmarkHardeningDemoRelease',
                'generateHardeningDemoReleaseR8Rules',
                'rewriteHardeningDemoReleaseBundle',
                'signHardeningDemoReleaseBundle',
                'gateHardeningDemoReleaseSimilarity',
                'validateHardeningDemoReleaseBundle',
                'assembleHardeningDemoReleaseUniversalApk',
            ]
            def androidHardeningWiringRequested = providers.provider {
                androidHardeningRequested.get() && gradle.startParameter.taskNames.any { requested ->
                    def separator = requested.lastIndexOf(':')
                    def requestedProjectPath = separator < 0 ? null : requested.substring(0, separator)
                    def normalizedProjectPath = requestedProjectPath == null || requestedProjectPath.startsWith(':')
                        ? requestedProjectPath
                        : ":${'$'}requestedProjectPath"
                    def taskName = requested.substring(separator + 1)
                    (normalizedProjectPath == null || normalizedProjectPath == project.path) &&
                        demoHardeningTaskNames.any { it.equalsIgnoreCase(taskName) }
                }
            }

            android {
                namespace = 'com.example.demo'
                compileSdk = 35
                buildFeatures {
                    buildConfig = true
                }
                defaultConfig {
                    applicationId = 'com.example.default'
                    minSdk = 26
                    targetSdk = 35
                    versionCode = 7
                    versionName = '1.0'
                    proguardFiles 'proguard-rules.pro'
                }
                lint {
                    checkReleaseBuilds = false
                }
                signingConfigs {
                    fixture {
                        storeFile = ${if (includeOwnedModules) "rootProject.file('fixture-signing.p12')" else "file('fixture-signing.p12')"}
                        storePassword = 'fixture-password'
                        keyAlias = 'fixture-key'
                        keyPassword = 'fixture-password'
                        storeType = 'PKCS12'
                    }
                    fixtureDebug {
                        storeFile = ${if (includeOwnedModules) "rootProject.file('fixture-debug-signing.p12')" else "file('fixture-debug-signing.p12')"}
                        storePassword = 'fixture-password'
                        keyAlias = 'fixture-debug-key'
                        keyPassword = 'fixture-password'
                        storeType = 'PKCS12'
                    }
                }
                flavorDimensions += 'channel'
                productFlavors {
                    demo {
                        dimension = 'channel'
                        applicationId = 'com.example.demo.app'
                        versionCode = 42
                        signingConfig = signingConfigs.fixture
                    }
                }
                buildTypes {
                    debug {
                        minifyEnabled = false
                        shrinkResources = false
                        signingConfig = signingConfigs.fixtureDebug
                    }
                    release {
                        minifyEnabled = true
                        shrinkResources = false
                        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
                    }
                }
            }

            ${if (includeOwnedModules) ownedModuleDependencies() else ""}

            androidHardening {
                enabled.set(providers.gradleProperty('androidHardening').map { it.toBoolean() }.orElse(false))
                projectKey.set('demo')
                variants.include('demoRelease')
                ${if (includeDebug) "variants.include('demoDebug')" else ""}
                ${if (includeOwnedModules) """
                ownership {
                    module(':app') { sourceSets.add('main') }
                    module(':core') { sourceSets.add('main') }
                    module(':compress') { sourceSets.add('main') }
                    module(':selector') { sourceSets.add('main') }
                    module(':ucrop') { sourceSets.add('main') }
                }
                """ else """
                ownership {
                    module(':') { sourceSets.add('main') }
                }
                """}
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
                mapping.storeDirectory.set(${if (includeOwnedModules) "rootProject.layout.projectDirectory" else "layout.projectDirectory"}.dir('fixture-state'))
                similarity.baselineDirectory.set(${if (includeOwnedModules) "rootProject.layout.projectDirectory" else "layout.projectDirectory"}.dir('fixture-baselines'))
                similarity.minimumImprovementPoints.set(${minimumImprovementPoints}d)
                similarity.maximumOverallExclusive.set(${maximumOverallExclusive}d)
                ${if (configureFixedSeed) """
                reproducibility {
                    fixedSeed.set(providers.gradleProperty('androidHardeningSeed'))
                }
                """.trimIndent() else ""}
            }

            tasks.register('showcaseReleaseSentinel') {
                doLast {
                    rootProject.file('showcase-sentinel-executed.txt').text = 'executed'
                    throw new GradleException('showcase sentinel executed')
                }
            }
            tasks.register('uploadHardeningSentinel') {
                doLast {
                    rootProject.file('upload-sentinel-executed.txt').text = 'executed'
                    throw new GradleException('upload sentinel executed')
                }
            }
            tasks.register('publishHardeningSentinel') {
                doLast {
                    rootProject.file('publish-sentinel-executed.txt').text = 'executed'
                    throw new GradleException('publish sentinel executed')
                }
            }
            gradle.taskGraph.whenReady {
                tasks.matching { it.name.startsWith('auditHardening') }.configureEach {
                    legacyPluginObservations.set(rootProject.file('fixture-legacy-plugin-observations.txt').readLines())
                }
            }
            """.trimIndent(),
        )
        if (includeOwnedModules) {
            listOf("core", "compress", "selector", "ucrop").forEach(::writeOwnedLibraryModule)
        }
    }

    private fun writeFixedSeedAndroidFixture() {
        writeAndroidFixture(100.0, false, false, true, 0.01, true)
    }

    private fun assertRawSeedAbsent(rawSeed: String, roots: List<Path>) {
        val needle = rawSeed.toByteArray(Charsets.UTF_8)
        roots.filter(Files::exists).forEach { root ->
            Files.walk(root).use { paths ->
                paths.filter(Files::isRegularFile).forEach { path ->
                    assertFalse(containsBytes(Files.readAllBytes(path), needle), "raw fixed seed found in $path")
                }
            }
        }
    }

    private fun containsBytes(bytes: ByteArray, needle: ByteArray): Boolean =
        needle.isNotEmpty() && (0..bytes.size - needle.size).any { start ->
            needle.indices.all { offset -> bytes[start + offset] == needle[offset] }
        }

    private fun ownedModuleDependencies(): String =
        """
        dependencies {
            implementation project(':core')
            implementation project(':compress')
            implementation project(':selector')
            implementation project(':ucrop')
        }
        """.trimIndent()

    private fun writeOwnedLibraryModule(module: String) {
        val moduleDirectory = projectDirectory.resolve(module)
        val simpleName = module.replaceFirstChar(Char::uppercaseChar)
        moduleDirectory.resolve("src/main/java/com/example/$module").createDirectories()
        moduleDirectory.resolve("src/main/java/com/example/$module/$simpleName.java").writeText(
            "package com.example.$module; public final class $simpleName { " +
                "public int measure() { return ${module.length}; } }\n",
        )
        moduleDirectory.resolve("src/main/AndroidManifest.xml").writeText("<manifest />\n")
        moduleDirectory.resolve("build.gradle").writeText(
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
            """.trimIndent(),
        )
    }

    private fun createFixtureKeyStore(fileName: String, alias: String, commonName: String) {
        val keyStore = projectDirectory.resolve(fileName)
        val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool")
        val process = ProcessBuilder(
            keytool.toString(),
            "-genkeypair",
            "-alias",
            alias,
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
            "CN=$commonName",
            "-noprompt",
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { "fixture keytool failed: $output" }
    }

    private fun certificateSha256(keyStorePath: Path, alias: String): String {
        val keyStore = KeyStore.getInstance("PKCS12")
        Files.newInputStream(keyStorePath).use { input ->
            keyStore.load(input, "fixture-password".toCharArray())
        }
        return sha256(requireNotNull(keyStore.getCertificate(alias)).encoded)
    }

    private fun sha256(path: Path): String = MessageDigest.getInstance("SHA-256")
        .digest(path.toFile().readBytes())
        .joinToString("") { byte -> "%02x".format(byte) }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte) }

    private fun stateFingerprint(root: Path): Map<String, String> = Files.walk(root).use { paths ->
        paths.filter { path -> path != root }
            .sorted()
            .toList()
            .associate { path ->
                val relative = root.relativize(path).toString().replace('\\', '/')
                if (Files.isDirectory(path)) "d:$relative" to "" else "f:$relative" to sha256(path)
            }
    }

    private fun jsonString(json: Map<*, *>, field: String): String =
        requireNotNull(json[field] as? String) { "missing JSON string field $field" }

    private fun jsonInt(json: Map<*, *>, field: String): Int =
        requireNotNull(json[field] as? Number) { "missing JSON integer field $field" }.toInt()

    private fun jsonObject(json: String): Map<*, *> =
        requireNotNull(JsonSlurper().parseText(json) as? Map<*, *>) { "expected a JSON object" }

    private fun jsonObject(json: Map<*, *>, field: String): Map<*, *> =
        requireNotNull(json[field] as? Map<*, *>) { "missing JSON object field $field" }

    private companion object {
        val FORBIDDEN_SENTINEL_MARKERS = listOf(
            "showcase-sentinel-executed.txt",
            "upload-sentinel-executed.txt",
            "publish-sentinel-executed.txt",
            "install-sentinel-executed.txt",
            "notify-sentinel-executed.txt",
        )
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
