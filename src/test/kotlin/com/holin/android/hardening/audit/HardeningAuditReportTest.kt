package com.holin.android.hardening.audit

import com.holin.android.hardening.LegacyPluginDeclaration
import com.holin.android.hardening.state.Sha256
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class HardeningAuditReportTest {
    @TempDir
    lateinit var directory: Path

    @Test
    fun `dependency inventory is deterministic and hashes every resolved file`() {
        val first = artifact("z.jar", byteArrayOf(3, 2, 1))
        val second = artifact("a.aar", byteArrayOf(1, 2, 3))

        val entries = RuntimeDependencyFingerprinter().fingerprint(
            listOf(
                RuntimeArtifactInput("org.example:z:1", first),
                RuntimeArtifactInput("org.example:a:2", second),
            ),
        )

        assertEquals(listOf("org.example:a:2", "org.example:z:1"), entries.map { it.component })
        assertTrue(entries.all { it.sha256.matches(Regex("[0-9a-f]{64}")) })
        assertEquals(listOf("a.aar", "z.jar"), entries.map { it.fileName })
    }

    @Test
    fun `legacy verifier requires the complete declared set once any plugin is expected`() {
        val observed = listOf(
            LegacyPluginObservation(
                pluginId = "io.github.qq549631030.android-junk-code",
                implementationClass = "cn.hx.plugin.junkcode.plugin.AndroidJunkCodePlugin",
                implementationArtifact = "android-junk-code-1.3.4.jar",
                implementationSha256 = "a".repeat(64),
                extensionName = "androidJunkCode",
                extensionClass = "cn.hx.plugin.junkcode.ext.AndroidJunkCodeExt",
                taskNames = listOf("generateDemoReleaseJunkCode"),
                taskClasses = listOf("cn.hx.plugin.junkcode.task.GenerateJunkCodeTask"),
            ),
        )

        val result = LegacyCompatibilityVerifier.verify(
            observed,
            listOf(
                LegacyPluginDeclaration(
                    "junkGenerator",
                    "io.github.qq549631030.android-junk-code",
                    "1.3.4",
                    emptyList(),
                    emptyList(),
                ),
                LegacyPluginDeclaration(
                    "otherLegacyPlugin",
                    "com.example.other-legacy-plugin",
                    "2.0.0",
                    emptyList(),
                    emptyList(),
                ),
            ),
        )

        assertEquals(LegacyCompatibilityStatus.FAIL, result.status)
        assertTrue(result.issues.any { it.contains("com.example.other-legacy-plugin") })
    }

    @Test
    fun `legacy verifier treats a reusable project with no legacy plugins as not applicable`() {
        val result = LegacyCompatibilityVerifier.verify(emptyList())

        assertEquals(LegacyCompatibilityStatus.NOT_APPLICABLE, result.status)
        assertTrue(result.issues.isEmpty())
    }

    @Test
    fun `legacy baseline rejects every pinned valid looking substituted implementation digest`() {
        listOf("io.github.qq549631030.android-junk-code", "xml-class-guard", "stringfog").forEach { pluginId ->
            val fixture = legacyBaselineFixture()
            val observations = pinnedLegacyObservations().map { observation ->
                if (observation.pluginId == pluginId) {
                    observation.copy(implementationSha256 = "b".repeat(64))
                } else {
                    observation
                }
            }

            val result = LegacyPluginBaselineVerifier.verify(fixture.baseline, fixture.root, observations)

            assertEquals(LegacyCompatibilityStatus.FAIL, result.status, pluginId)
            assertTrue(result.issues.any { it.contains(pluginId) && it.contains("implementation checksum differs") })
        }
    }

    @Test
    fun `legacy baseline accepts the exact pinned sources and observations`() {
        val fixture = legacyBaselineFixture()

        val result = LegacyPluginBaselineVerifier.verify(
            fixture.baseline,
            fixture.root,
            pinnedLegacyObservations(),
        )

        assertEquals(LegacyCompatibilityStatus.PASS, result.status, result.issues.toString())
        assertTrue(result.issues.isEmpty())
    }

    @Test
    fun `legacy baseline accepts matching portable declarations and a missing mapping path`() {
        val fixture = legacyBaselineFixture()
        assertTrue(!fixture.root.resolve("app/xml-class-mapping.txt").exists())

        val result = LegacyPluginBaselineVerifier.verify(
            fixture.baseline,
            fixture.root,
            pinnedLegacyObservations(),
            pinnedLegacyDeclarations(),
        )

        assertEquals(LegacyCompatibilityStatus.PASS, result.status)
        assertTrue(result.issues.isEmpty())
    }

    @Test
    fun `legacy baseline reports a mismatched declaration`() {
        val fixture = legacyBaselineFixture()
        val declarations = pinnedLegacyDeclarations().map { declaration ->
            if (declaration.name == "stringFog") declaration.copy(expectedVersion = "5.2.1") else declaration
        }

        val result = LegacyPluginBaselineVerifier.verify(
            fixture.baseline,
            fixture.root,
            pinnedLegacyObservations(),
            declarations,
        )

        assertEquals(LegacyCompatibilityStatus.FAIL, result.status)
        assertTrue(result.issues.any { it == "legacy plugin stringFog expectedVersion differs from its baseline" })
    }

    @Test
    fun `legacy baseline reports an unexpected declaration`() {
        val fixture = legacyBaselineFixture()
        val unexpected = LegacyPluginDeclaration(
            "unexpected",
            "com.example.unexpected",
            "9.9.9",
            emptyList(),
            emptyList(),
        )

        val result = LegacyPluginBaselineVerifier.verify(
            fixture.baseline,
            fixture.root,
            pinnedLegacyObservations(),
            pinnedLegacyDeclarations() + unexpected,
        )

        assertEquals(LegacyCompatibilityStatus.FAIL, result.status)
        assertTrue(result.issues.any { it == "unexpected legacy plugin declaration unexpected" })
    }

    @Test
    fun `portable schema accepts an arbitrary non product legacy plugin`() {
        val fixture = portableLegacyBaselineFixture()

        val result = LegacyPluginBaselineVerifier.verify(
            fixture.baseline,
            fixture.root,
            listOf(fixture.observation),
            listOf(fixture.declaration),
        )

        assertEquals(LegacyCompatibilityStatus.PASS, result.status, result.issues.toString())
        assertTrue(result.issues.isEmpty())
    }

    @Test
    fun `legacy baseline is mandatory for a full audit`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            LegacyPluginBaselineVerifier.verifyRequired(
                baselineFile = null,
                repositoryRoot = directory,
                observations = emptyList(),
            )
        }

        assertTrue(failure.message.orEmpty().contains("baseline is required"))
    }

    @Test
    fun `legacy baseline rejects a changed active version with pinned text left in a comment`() {
        val fixture = legacyBaselineFixture()
        val catalog = fixture.root.resolve("gradle/libs.versions.toml")
        val original = catalog.readText()
        val pinned = "stringFogXor = \"5.0.0\""
        require(original.contains(pinned))
        catalog.writeText(original.replace(pinned, "stringFogXor = \"5.1.0\" # $pinned"))

        val result = LegacyPluginBaselineVerifier.verify(
            fixture.baseline,
            fixture.root,
            pinnedLegacyObservations(),
        )

        assertEquals(LegacyCompatibilityStatus.FAIL, result.status)
        assertTrue(result.issues.any { it.contains("version source mismatch: stringFogRuntime") })
    }

    @Test
    fun `legacy baseline rejects a changed plugin version source`() {
        val fixture = legacyBaselineFixture()
        val catalog = fixture.root.resolve("gradle/libs.versions.toml")
        val original = catalog.readText()
        val pinned = "stringFogPlugin = \"5.2.0\""
        assertTrue(original.contains(pinned))
        catalog.writeText(original.replace(pinned, "stringFogPlugin = \"5.2.1\""))

        val result = LegacyPluginBaselineVerifier.verify(
            fixture.baseline,
            fixture.root,
            pinnedLegacyObservations(),
        )

        assertEquals(LegacyCompatibilityStatus.FAIL, result.status)
        assertTrue(result.issues.any { it.contains("version source mismatch: stringFogPlugin") })
    }

    @Test
    fun `legacy baseline rejects every pinned extension and task identity mutation`() {
        val mutations = listOf<Pair<String, (LegacyPluginObservation) -> LegacyPluginObservation>>(
            "extension name" to { it.copy(extensionName = "changedExtension") },
            "extension class" to { it.copy(extensionClass = "changed.Extension") },
            "task names" to { it.copy(taskNames = listOf("changedTask")) },
            "task classes" to { it.copy(taskClasses = listOf("changed.Task")) },
        )

        mutations.forEach { (label, mutate) ->
            val fixture = legacyBaselineFixture()
            val observations = pinnedLegacyObservations().map { observation ->
                if (observation.pluginId == "stringfog") mutate(observation) else observation
            }

            val result = LegacyPluginBaselineVerifier.verify(fixture.baseline, fixture.root, observations)

            assertEquals(LegacyCompatibilityStatus.FAIL, result.status, label)
            assertTrue(result.issues.any { it.contains(label) }, "$label was not reported: ${result.issues}")
        }
    }

    @Test
    fun `legacy baseline rejects every frozen DSL and application region mutation`() {
        val mutations = listOf(
            "legacyPluginApplications" to ("    id(\"xml-class-guard\")\n" to "    id(\"xml-class-guard-mutated\")\n"),
            "androidJunkCodeDsl" to ("    androidJunkCode {\n" to "    androidJunkCode { \n"),
            "xmlClassGuardDsl" to ("    xmlClassGuard {\n" to "    xmlClassGuard { \n"),
            "stringFogDsl" to ("configure<StringFogExtension> {\n" to "configure<StringFogExtension> { \n"),
        )

        mutations.forEach { (region, replacement) ->
            val fixture = legacyBaselineFixture()
            val appBuild = fixture.root.resolve("app/build.gradle.kts")
            val original = appBuild.readText()
            require(original.contains(replacement.first))
            appBuild.writeText(original.replace(replacement.first, replacement.second))

            val result = LegacyPluginBaselineVerifier.verify(
                fixture.baseline,
                fixture.root,
                pinnedLegacyObservations(),
            )

            assertEquals(LegacyCompatibilityStatus.FAIL, result.status, region)
            assertTrue(result.issues.any { it.contains(region) }, "$region was not reported: ${result.issues}")
        }
    }

    @Test
    fun `report codec is deterministic and passing decoder rejects failed report`() {
        val base = HardeningAuditReport(
            variant = "demoRelease",
            namespace = "com.example",
            status = HardeningAuditStatus.PASS,
            productionSourceFiles = listOf("z.kt", "a.kt"),
            resolvedContracts = emptyList(),
            unresolvedContracts = emptyList(),
            externalNameCandidates = emptyList(),
            legacyCompatibility = LegacyCompatibilityResult(
                LegacyCompatibilityStatus.NOT_APPLICABLE,
                emptyList(),
                emptyList(),
            ),
            runtimeDependencies = emptyList(),
            r8RulesManifestSha256 = "b".repeat(64),
        )

        val encoded = HardeningAuditReportCodec.encode(base)

        assertEquals(encoded, HardeningAuditReportCodec.encode(base.copy(productionSourceFiles = listOf("a.kt", "z.kt"))))
        assertEquals(HardeningAuditStatus.PASS, HardeningAuditReportCodec.decodeStatus(encoded))
        val failed = encoded.replace("\"status\":\"PASS\"", "\"status\":\"FAIL\"")
        assertFailsWith<IllegalArgumentException> { HardeningAuditReportCodec.requirePassing(failed) }
    }

    @Test
    fun `report codec records effective hardcoded scope and categorized findings deterministically`() {
        val sensitiveUrl = "https://username:password@api.example.test/private/path?token=secret#fragment"
        val sensitiveUri = "demo://username:password@private/path?token=secret#fragment"
        val report = HardeningAuditReport(
            "demoRelease",
            "com.example",
            HardeningAuditStatus.PASS,
            emptyList(),
            emptyList(),
            emptyList(),
            emptyList(),
            LegacyCompatibilityResult(LegacyCompatibilityStatus.NOT_APPLICABLE, emptyList(), emptyList()),
            emptyList(),
            "b".repeat(64),
            emptyList(),
            HardcodedReferenceScopeReport(
                listOf("URL", "URI", "ROUTE"),
                listOf("**/*.kt"),
                listOf("**/test/**"),
                true,
            ),
            listOf(
                HardcodedReferenceFinding(com.holin.android.hardening.HardcodedReferenceKind.URL, "src/A.kt", 3, sensitiveUrl),
                HardcodedReferenceFinding(com.holin.android.hardening.HardcodedReferenceKind.URI, "src/A.kt", 4, sensitiveUri),
            ),
            listOf(UnresolvedHardcodedReference(com.holin.android.hardening.HardcodedReferenceKind.CLASS_NAME, "src/A.kt", 4, "Class.forName(remote)", "dynamic")),
        )

        val encoded = HardeningAuditReportCodec.encode(report)

        assertTrue(encoded.contains("\"hardcodedReferenceScope\":{\"kinds\":[\"ROUTE\",\"URI\",\"URL\"]"))
        assertTrue(encoded.contains("\"kind\":\"URL\""))
        assertTrue(encoded.contains("\"kind\":\"URI\""))
        assertTrue(encoded.contains("\"unresolvedHardcodedReferences\":[{\"kind\":\"CLASS_NAME\""))
        assertTrue(encoded.contains("\"value\":\"https://<redacted>\""))
        assertTrue(encoded.contains("\"value\":\"demo://<redacted>\""))
        assertTrue(encoded.contains("\"valueSha256\":\"${Sha256.hex(sensitiveUrl.toByteArray())}\""))
        assertTrue(encoded.contains("\"valueSha256\":\"${Sha256.hex(sensitiveUri.toByteArray())}\""))
        listOf("username", "password", "private", "path", "token", "secret", "fragment").forEach { secret ->
            assertFalse(encoded.contains(secret), "report leaked $secret")
        }
    }

    private fun artifact(name: String, bytes: ByteArray): Path = directory.resolve(name).also { path ->
        path.parent.createDirectories()
        path.writeBytes(bytes)
    }

    private fun legacyBaselineFixture(): LegacyFixture {
        val root = directory.resolve("legacy-${java.util.UUID.randomUUID()}")
        val appBuild = root.resolve("app/build.gradle.kts")
        val rootBuild = root.resolve("build.gradle.kts")
        val versionCatalog = root.resolve("gradle/libs.versions.toml")
        val baseline = root.resolve("app/hardening/legacy-plugins-baseline.json")
        appBuild.parent.createDirectories()
        versionCatalog.parent.createDirectories()
        baseline.parent.createDirectories()
        val applicationLines = listOf(
            "    id(\"io.github.qq549631030.android-junk-code\")\n",
            "    id(\"xml-class-guard\")\n",
            "    id(\"stringfog\")\n",
        )
        val junkDsl = "    androidJunkCode {\n        enabled.set(true)\n    }"
        val guardDsl = "    xmlClassGuard {\n        enabled.set(true)\n    }"
        val fogDsl = "configure<StringFogExtension> {\n    enabled.set(true)\n}"
        appBuild.writeText(
            "plugins {\n" + applicationLines.joinToString("") + "}\n\n" +
                "$junkDsl\n\n$guardDsl\n\n$fogDsl\n",
        )
        rootBuild.writeText(
            "id(\"io.github.qq549631030.android-junk-code\") version \"1.3.4\" apply false\n",
        )
        versionCatalog.writeText(
            "[versions]\nxmlClassGuard = \"1.2.6\"\nstringFogPlugin = \"5.2.0\"\nstringFogXor = \"5.0.0\"\n",
        )
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
                  "appBuild": {
                    "path": "app/build.gradle.kts",
                    "sourceRevision": "git-blob:fixture-app-build",
                    "sha256": "${Sha256.file(appBuild)}"
                  },
                  "rootBuild": {
                    "path": "build.gradle.kts",
                    "sourceRevision": "git-blob:fixture-root-build",
                    "sha256": "${Sha256.file(rootBuild)}"
                  },
                  "versionCatalog": {
                    "path": "gradle/libs.versions.toml",
                    "sourceRevision": "git-blob:fixture-version-catalog",
                    "sha256": "${Sha256.file(versionCatalog)}"
                  }
                },
                "regions": {
                  "legacyPluginApplications": {
                    "algorithm": "ordered-exact-lines",
                    "file": "appBuild",
                    "lines": [
                      "    id(\"io.github.qq549631030.android-junk-code\")${'\\'}n",
                      "    id(\"xml-class-guard\")${'\\'}n",
                      "    id(\"stringfog\")${'\\'}n"
                    ]
                  },
                  "androidJunkCodeDsl": {
                    "algorithm": "balanced-brace-block",
                    "file": "appBuild",
                    "startMarker": "    androidJunkCode {${'\\'}n"
                  },
                  "xmlClassGuardDsl": {
                    "algorithm": "balanced-brace-block",
                    "file": "appBuild",
                    "startMarker": "    xmlClassGuard {${'\\'}n"
                  },
                  "stringFogDsl": {
                    "algorithm": "balanced-brace-block",
                    "file": "appBuild",
                    "startMarker": "configure<StringFogExtension> {${'\\'}n"
                  }
                }
              },
              "frozenRegions": {
                "legacyPluginApplications": {
                  "file": "appBuild",
                  "lineCount": 3,
                  "sha256": "${Sha256.hex(applicationLines.joinToString("").toByteArray())}"
                },
                "androidJunkCodeDsl": {
                  "file": "appBuild",
                  "sha256": "${Sha256.hex(junkDsl.toByteArray())}"
                },
                "xmlClassGuardDsl": {
                  "file": "appBuild",
                  "sha256": "${Sha256.hex(guardDsl.toByteArray())}"
                },
                "stringFogDsl": {
                  "file": "appBuild",
                  "sha256": "${Sha256.hex(fogDsl.toByteArray())}"
                }
              },
              "versionSources": {
                "junkRuntime": {
                  "path": "build.gradle.kts",
                  "literal": "id(\"io.github.qq549631030.android-junk-code\") version \"1.3.4\" apply false"
                },
                "xmlGuardRuntime": {
                  "path": "gradle/libs.versions.toml",
                  "literal": "xmlClassGuard = \"1.2.6\""
                },
                "stringFogPlugin": {
                  "path": "gradle/libs.versions.toml",
                  "literal": "stringFogPlugin = \"5.2.0\""
                },
                "stringFogRuntime": {
                  "path": "gradle/libs.versions.toml",
                  "literal": "stringFogXor = \"5.0.0\""
                }
              },
              "plugins": [
                {
                  "name": "androidJunkCode",
                  "pluginId": "io.github.qq549631030.android-junk-code",
                  "expectedVersion": "1.3.4",
                  "implementationClass": "cn.hx.plugin.junkcode.plugin.AndroidJunkCodePlugin",
                  "jarSha256": "6ca9ebff4a06767aa31bee36ec32ef7813894b2ee16a7f80f41a29ade2b49219",
                  "extensionName": "androidJunkCode",
                  "extensionClass": "cn.hx.plugin.junkcode.ext.AndroidJunkCodeExt_Decorated",
                  "taskNames": ["generateDemoReleaseJunkCode"],
                  "taskClasses": [
                    "cn.hx.plugin.junkcode.task.GenerateJunkCodeTask",
                    "cn.hx.plugin.junkcode.task.GenerateJunkCodeTask_Decorated",
                    "java.lang.Object",
                    "org.gradle.api.DefaultTask",
                    "org.gradle.api.internal.AbstractTask"
                  ],
                  "configurationInputs": ["app/build.gradle.kts", "build.gradle.kts"],
                  "mappingPaths": [],
                  "frozenRegions": ["androidJunkCodeDsl", "legacyPluginApplications"],
                  "versionSources": ["junkRuntime"]
                },
                {
                  "name": "stringFog",
                  "pluginId": "stringfog",
                  "expectedVersion": "5.2.0",
                  "implementationClass": "com.github.megatronking.stringfog.plugin.StringFogPlugin",
                  "jarSha256": "2fa8c35ce2a5a2dfdcc225b8762cc1064f5946f2771ef92fcf22a241f9583756",
                  "extensionName": "stringfog",
                  "extensionClass": "com.github.megatronking.stringfog.plugin.StringFogExtension_Decorated",
                  "taskNames": [
                    "generateStringFogDemoDebug",
                    "generateStringFogDemoRelease",
                    "generateStringFogShowcaseDebug",
                    "generateStringFogShowcaseRelease"
                  ],
                  "taskClasses": [
                    "com.github.megatronking.stringfog.plugin.SourceGeneratingTask",
                    "com.github.megatronking.stringfog.plugin.SourceGeneratingTask_Decorated",
                    "java.lang.Object",
                    "org.gradle.api.DefaultTask",
                    "org.gradle.api.internal.AbstractTask"
                  ],
                  "configurationInputs": ["app/build.gradle.kts", "gradle/libs.versions.toml"],
                  "mappingPaths": [],
                  "frozenRegions": ["stringFogDsl"],
                  "versionSources": ["stringFogPlugin", "stringFogRuntime"]
                },
                {
                  "name": "xmlClassGuard",
                  "pluginId": "xml-class-guard",
                  "expectedVersion": "1.2.6",
                  "implementationClass": "com.xml.guard.XmlClassGuardPlugin",
                  "jarSha256": "fd0bff574e52a9ed6982da54724fd92a472dc9c2ad830af8e95b8c58ff63547a",
                  "extensionName": "xmlClassGuard",
                  "extensionClass": "com.xml.guard.entensions.GuardExtension_Decorated",
                  "taskNames": [
                    "xmlClassGuardDemoDebug",
                    "xmlClassGuardDemoRelease",
                    "xmlClassGuardShowcaseDebug",
                    "xmlClassGuardShowcaseRelease"
                  ],
                  "taskClasses": [
                    "com.xml.guard.tasks.XmlClassGuardTask",
                    "com.xml.guard.tasks.XmlClassGuardTask_Decorated",
                    "java.lang.Object",
                    "org.gradle.api.DefaultTask",
                    "org.gradle.api.internal.AbstractTask"
                  ],
                  "configurationInputs": ["app/build.gradle.kts", "gradle/libs.versions.toml"],
                  "mappingPaths": ["app/xml-class-mapping.txt"],
                  "frozenRegions": ["xmlClassGuardDsl"],
                  "versionSources": ["xmlGuardRuntime"]
                }
              ]
            }
            """.trimIndent() + "\n",
        )
        return LegacyFixture(root, baseline)
    }

    private fun pinnedLegacyObservations(): List<LegacyPluginObservation> = listOf(
        LegacyPluginObservation(
            pluginId = "io.github.qq549631030.android-junk-code",
            implementationClass = "cn.hx.plugin.junkcode.plugin.AndroidJunkCodePlugin",
            implementationArtifact = "android-junk-code-1.3.4.jar",
            implementationSha256 = "6ca9ebff4a06767aa31bee36ec32ef7813894b2ee16a7f80f41a29ade2b49219",
            extensionName = "androidJunkCode",
            extensionClass = "cn.hx.plugin.junkcode.ext.AndroidJunkCodeExt_Decorated",
            taskNames = listOf("generateDemoReleaseJunkCode"),
            taskClasses = listOf(
                "cn.hx.plugin.junkcode.task.GenerateJunkCodeTask",
                "cn.hx.plugin.junkcode.task.GenerateJunkCodeTask_Decorated",
                "java.lang.Object",
                "org.gradle.api.DefaultTask",
                "org.gradle.api.internal.AbstractTask",
            ),
        ),
        LegacyPluginObservation(
            pluginId = "xml-class-guard",
            implementationClass = "com.xml.guard.XmlClassGuardPlugin",
            implementationArtifact = "xml-class-guard-1.2.6.jar",
            implementationSha256 = "fd0bff574e52a9ed6982da54724fd92a472dc9c2ad830af8e95b8c58ff63547a",
            extensionName = "xmlClassGuard",
            extensionClass = "com.xml.guard.entensions.GuardExtension_Decorated",
            taskNames = listOf(
                "xmlClassGuardDemoDebug",
                "xmlClassGuardDemoRelease",
                "xmlClassGuardShowcaseDebug",
                "xmlClassGuardShowcaseRelease",
            ),
            taskClasses = listOf(
                "com.xml.guard.tasks.XmlClassGuardTask",
                "com.xml.guard.tasks.XmlClassGuardTask_Decorated",
                "java.lang.Object",
                "org.gradle.api.DefaultTask",
                "org.gradle.api.internal.AbstractTask",
            ),
        ),
        LegacyPluginObservation(
            pluginId = "stringfog",
            implementationClass = "com.github.megatronking.stringfog.plugin.StringFogPlugin",
            implementationArtifact = "stringfog-gradle-plugin-5.2.0.jar",
            implementationSha256 = "2fa8c35ce2a5a2dfdcc225b8762cc1064f5946f2771ef92fcf22a241f9583756",
            extensionName = "stringfog",
            extensionClass = "com.github.megatronking.stringfog.plugin.StringFogExtension_Decorated",
            taskNames = listOf(
                "generateStringFogDemoDebug",
                "generateStringFogDemoRelease",
                "generateStringFogShowcaseDebug",
                "generateStringFogShowcaseRelease",
            ),
            taskClasses = listOf(
                "com.github.megatronking.stringfog.plugin.SourceGeneratingTask",
                "com.github.megatronking.stringfog.plugin.SourceGeneratingTask_Decorated",
                "java.lang.Object",
                "org.gradle.api.DefaultTask",
                "org.gradle.api.internal.AbstractTask",
            ),
        ),
    )

    private fun pinnedLegacyDeclarations(): List<LegacyPluginDeclaration> = listOf(
        LegacyPluginDeclaration(
            "androidJunkCode",
            "io.github.qq549631030.android-junk-code",
            "1.3.4",
            listOf("app/build.gradle.kts", "build.gradle.kts"),
            emptyList(),
        ),
        LegacyPluginDeclaration(
            "stringFog",
            "stringfog",
            "5.2.0",
            listOf("app/build.gradle.kts", "gradle/libs.versions.toml"),
            emptyList(),
        ),
        LegacyPluginDeclaration(
            "xmlClassGuard",
            "xml-class-guard",
            "1.2.6",
            listOf("app/build.gradle.kts", "gradle/libs.versions.toml"),
            listOf("app/xml-class-mapping.txt"),
        ),
    )

    private fun portableLegacyBaselineFixture(): PortableLegacyFixture {
        val root = directory.resolve("portable-${java.util.UUID.randomUUID()}")
        val consumer = root.resolve("consumer/build.gradle.kts")
        val rootBuild = root.resolve("build.gradle.kts")
        val baseline = root.resolve("hardening/legacy-plugins-baseline.json")
        consumer.parent.createDirectories()
        baseline.parent.createDirectories()
        consumer.writeText(
            """
            plugins {
                id("com.acme.legacy")
            }
            legacyThing {
                enabled.set(true)
            }
            """.trimIndent() + "\n",
        )
        rootBuild.writeText("id(\"com.acme.legacy\") version \"7.4.2\" apply false\n")
        val applicationLine = "    id(\"com.acme.legacy\")\n"
        val dslBlock = "legacyThing {\n    enabled.set(true)\n}"
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
                  "consumerBuild": {
                    "path": "consumer/build.gradle.kts",
                    "sourceRevision": "git-blob:fixture-consumer",
                    "sha256": "${Sha256.file(consumer)}"
                  }
                },
                "regions": {
                  "pluginApplication": {
                    "algorithm": "ordered-exact-lines",
                    "file": "consumerBuild",
                    "lines": ["    id(\"com.acme.legacy\")${'\\'}n"]
                  },
                  "pluginDsl": {
                    "algorithm": "balanced-brace-block",
                    "file": "consumerBuild",
                    "startMarker": "legacyThing {${'\\'}n"
                  }
                }
              },
              "frozenRegions": {
                "pluginApplication": {
                  "file": "consumerBuild",
                  "lineCount": 1,
                  "sha256": "${Sha256.hex(applicationLine.toByteArray())}"
                },
                "pluginDsl": {
                  "file": "consumerBuild",
                  "sha256": "${Sha256.hex(dslBlock.toByteArray())}"
                }
              },
              "versionSources": {
                "pluginVersion": {
                  "path": "build.gradle.kts",
                  "literal": "id(\"com.acme.legacy\") version \"7.4.2\" apply false"
                }
              },
              "plugins": [
                {
                  "name": "acmeLegacy",
                  "pluginId": "com.acme.legacy",
                  "expectedVersion": "7.4.2",
                  "implementationClass": "com.acme.LegacyPlugin",
                  "jarSha256": "${"d".repeat(64)}",
                  "extensionName": "legacyThing",
                  "extensionClass": "com.acme.LegacyExtension",
                  "taskNames": ["generateDemoQaLegacy"],
                  "taskClasses": ["com.acme.LegacyTask"],
                  "configurationInputs": ["build.gradle.kts", "consumer/build.gradle.kts"],
                  "mappingPaths": ["consumer/missing-legacy-map.txt"],
                  "frozenRegions": ["pluginApplication", "pluginDsl"],
                  "versionSources": ["pluginVersion"]
                }
              ]
            }
            """.trimIndent() + "\n",
        )
        return PortableLegacyFixture(
            root,
            baseline,
            LegacyPluginObservation(
                "com.acme.legacy",
                "com.acme.LegacyPlugin",
                "acme-legacy-7.4.2.jar",
                "d".repeat(64),
                "legacyThing",
                "com.acme.LegacyExtension",
                listOf("generateDemoQaLegacy"),
                listOf("com.acme.LegacyTask"),
            ),
            LegacyPluginDeclaration(
                "acmeLegacy",
                "com.acme.legacy",
                "7.4.2",
                listOf("build.gradle.kts", "consumer/build.gradle.kts"),
                listOf("consumer/missing-legacy-map.txt"),
            ),
        )
    }

    private data class LegacyFixture(val root: Path, val baseline: Path)
    private data class PortableLegacyFixture(
        val root: Path,
        val baseline: Path,
        val observation: LegacyPluginObservation,
        val declaration: LegacyPluginDeclaration,
    )
}
