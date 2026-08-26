package com.holin.android.hardening.tasks

import com.android.aapt.Resources
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile
import com.android.tools.smali.dexlib2.writer.io.MemoryDataStore
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import com.holin.android.hardening.similarity.HardeningBaselineCaptureRequest
import com.holin.android.hardening.similarity.ImmutableHardeningBaselineStore
import com.holin.android.hardening.similarity.OwnedArtifactAnalyzer
import com.holin.android.hardening.similarity.OwnedArtifactAnalysisRequest
import com.holin.android.hardening.similarity.OwnedArtifactInventory
import com.holin.android.hardening.similarity.OwnedArtifactInventoryCodec
import com.holin.android.hardening.similarity.OwnedArtifactSimilarityScorerV1
import com.holin.android.hardening.similarity.OwnedResourceKey
import com.holin.android.hardening.similarity.OwnedResourceLocation
import com.holin.android.hardening.similarity.RelativeSimilarityGateException
import com.holin.android.hardening.similarity.ValidatedOwnedArtifactInventories
import com.holin.android.hardening.state.ArchiveRequest
import com.holin.android.hardening.state.HardeningStateLockService
import com.holin.android.hardening.state.PortableBaselineIdentityMigration
import com.holin.android.hardening.state.PortableStateIdentityMigration
import com.holin.android.hardening.state.PortableStateMigrationDescriptor
import com.holin.android.hardening.state.PortableStateMigrationDescriptorCodec
import com.holin.android.hardening.state.PrepareRequest
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StateCoordinates
import com.holin.android.hardening.state.StateStore
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createDirectories
import kotlin.io.path.outputStream
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertFails
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.io.TempDir

class CompareHardeningSimilarityTaskTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `comparison uses identity hash and changed analysis locations`() {
        val root = repository.toRealPath()
        val inputs = root.resolve("inputs").createDirectories()
        val dex = ownedDex()
        val ordinaryAab = artifact(
            inputs.resolve("ordinary.aab"),
            "base/dex/classes.dex" to dex,
            "base/resources.pb" to resourceTable(ORDINARY_AAB_PATH),
            ORDINARY_AAB_PATH to RESOURCE_BYTES,
        )
        val ordinaryApk = artifact(
            inputs.resolve("ordinary.apk"),
            "classes.dex" to dex,
            ORDINARY_APK_PATH to RESOURCE_BYTES,
        )
        val hardenedAab = artifact(
            inputs.resolve("hardened.aab"),
            "base/dex/classes.dex" to dex,
            "base/resources.pb" to resourceTable(ANALYSIS_AAB_PATH),
            ANALYSIS_AAB_PATH to RESOURCE_BYTES,
        )
        val hardenedApk = artifact(
            inputs.resolve("hardened.apk"),
            "classes.dex" to dex,
            ANALYSIS_APK_PATH to RESOURCE_BYTES,
        )
        val identity = inventory(IDENTITY_AAB_PATH, IDENTITY_APK_PATH)
        val analysis = inventory(ANALYSIS_AAB_PATH, ANALYSIS_APK_PATH)
        assertNotEquals(identity.ownershipSha256, analysis.ownershipSha256)
        ValidatedOwnedArtifactInventories(identity, analysis)
        val analysisRequest = OwnedArtifactAnalysisRequest(
            ordinaryAab = ordinaryAab,
            hardenedAab = hardenedAab,
            ordinaryUniversalApk = ordinaryApk,
            hardenedUniversalApk = hardenedApk,
            ownedDescriptors = analysis.ownedDescriptors,
            ordinaryOwnedResources = analysis.ordinaryOwnedResources,
            hardenedOwnedResources = analysis.hardenedOwnedResources,
        )
        val (ordinary, hardened) = OwnedArtifactAnalyzer().analyzePair(analysisRequest)
        val baselineReport = OwnedArtifactSimilarityScorerV1.compare(ordinary, hardened)
        val baselineDirectory = root.resolve("fixture-baselines")
        ImmutableHardeningBaselineStore(root, baselineDirectory).capture(
            HardeningBaselineCaptureRequest(
                "demo",
                "demoDebug",
                ordinaryAab,
                hardenedAab,
                ordinaryApk,
                hardenedApk,
                OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
                LEGACY_OWNERSHIP_SHA256,
                LEGACY_CONFIGURATION_SHA256,
                baselineReport,
            ),
        )
        val identityFile = inputs.resolve("owned-artifact-inventory.json").also { path ->
            path.writeText(OwnedArtifactInventoryCodec.encode(identity))
        }
        val analysisFile = inputs.resolve("owned-artifact-analysis-inventory.json").also { path ->
            path.writeText(OwnedArtifactInventoryCodec.encode(analysis))
        }
        val currentMapping = inputs.resolve("current-mapping.txt").also { path ->
            path.writeText("com.example.demo.match.Owned -> com.example.demo.match.Owned:\n")
        }
        val mappingStore = root.resolve(".hardening/mappings")
        archiveBaselineMapping(mappingStore, inputs.resolve("baseline-prepared"), hardenedAab, currentMapping)
        val project = ProjectBuilder.builder().withProjectDir(root.toFile()).build()
        val legacyBaselineRoot = baselineDirectory.resolve("demo/demoDebug/v1")
        val legacyPayloadSha256 = Sha256.canonicalPayload(legacyBaselineRoot)
        val migrationDescriptor = inputs.resolve("portable-state-migration.json").also { path ->
            path.writeText(
                PortableStateMigrationDescriptorCodec.encode(
                    PortableStateMigrationDescriptor(
                        2,
                        "demo",
                        "demoDebug",
                        PortableStateIdentityMigration(
                            "com.example.demo.match",
                            "com.example.demo.match",
                            "legacy-v1",
                            "com.holin.android.hardening/1.2.0",
                            "1".repeat(64),
                            "2".repeat(64),
                            "00000000-0000-0000-0000-000000000001",
                            1,
                            "3".repeat(64),
                            "4".repeat(64),
                            "5".repeat(64),
                            "6".repeat(64),
                        ),
                        PortableBaselineIdentityMigration(
                            OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
                            LEGACY_OWNERSHIP_SHA256,
                            LEGACY_CONFIGURATION_SHA256,
                            CONFIGURATION_SHA256,
                            legacyPayloadSha256,
                        ),
                    ),
                ),
            )
        }
        val lockService = project.gradle.sharedServices.registerIfAbsent(
            "testHardeningStateLock",
            HardeningStateLockService::class.java,
        ) {
            parameters.lockFile.set(
                project.layout.file(
                    project.provider { mappingStore.resolve("demo/demoDebug/locks/state.lock").toFile() },
                ),
            )
            parameters.projectPath.set(project.path)
            parameters.variant.set("demoDebug")
            parameters.timeoutSeconds.set(1)
            parameters.stateBoundary.set(project.layout.projectDirectory)
        }
        val task = project.tasks.register("compare", CompareHardeningSimilarityTask::class.java).get().apply {
            projectKey.set("demo")
            variantName.set("demoDebug")
            configurationSha256.set(CONFIGURATION_SHA256)
            minimumImprovementPoints.set(0.01)
            autoMigrateLegacyState.set(true)
            this.migrationDescriptor.set(migrationDescriptor.toFile())
            ordinaryBundle.set(ordinaryAab.toFile())
            hardenedBundle.set(hardenedAab.toFile())
            ordinaryUniversalApk.set(ordinaryApk.toFile())
            hardenedUniversalApk.set(hardenedApk.toFile())
            ownedArtifactInventory.set(identityFile.toFile())
            ownedArtifactAnalysisInventory.set(analysisFile.toFile())
            currentR8Mapping.set(currentMapping.toFile())
            mappingStoreDirectory.set(project.layout.dir(project.provider { mappingStore.toFile() }))
            baselineRoot.set(
                project.layout.dir(
                    project.provider {
                        baselineDirectory.resolve("demo/demoDebug/v1").toFile()
                    },
                ),
            )
            jsonReport.set(root.resolve("reports/similarity.json").toFile())
            markdownReport.set(root.resolve("reports/similarity.md").toFile())
            this.baselineDirectory.set(project.layout.dir(project.provider { baselineDirectory.toFile() }))
            repositoryRoot.set(project.layout.projectDirectory)
            artifactBoundary.set(project.layout.projectDirectory)
            this.lockService.set(lockService)
        }

        val failure = assertFails { task.compare() }
        assertIs<RelativeSimilarityGateException>(
            failure,
            "unexpected comparison failure: ${failure::class.qualifiedName}: ${failure.message}",
        )
        assertTrue(task.jsonReport.get().asFile.isFile)
        assertTrue(task.markdownReport.get().asFile.isFile)
        assertTrue(baselineDirectory.resolve("demo/demoDebug/active.json").toFile().isFile)
        assertTrue(
            baselineDirectory.resolve("demo/demoDebug/versions/$CONFIGURATION_SHA256/baseline.json")
                .toFile()
                .isFile,
        )
        assertTrue(legacyPayloadSha256 == Sha256.canonicalPayload(legacyBaselineRoot))
    }

    private fun archiveBaselineMapping(
        mappingStore: Path,
        preparedDirectory: Path,
        hardenedAab: Path,
        mapping: Path,
    ) {
        val root = mappingStore.resolve("demo/demoDebug")
        val store = StateStore()
        val prepared = store.prepare(
            PrepareRequest(
                root,
                StateCoordinates(
                    "demo",
                    "demoDebug",
                    "com.example.demo.match",
                    "com.example.demo.match",
                    CONFIGURATION_SHA256,
                ),
                preparedDirectory,
                "d".repeat(64),
                true,
                true,
                true,
            ),
        )
        prepared.preparedDirectory.resolve("mapping.txt").writeText(mapping.toFile().readText())
        store.archive(ArchiveRequest(prepared, 1, Sha256.file(hardenedAab)))
    }

    private fun inventory(hardenedAabPath: String, hardenedApkPath: String) = OwnedArtifactInventory(
        ownedModules = setOf(":app", ":core", ":compress", ":selector", ":ucrop"),
        ownedDescriptors = setOf(OWNED_DESCRIPTOR),
        ordinaryOwnedResources = mapOf(
            RESOURCE_KEY to OwnedResourceLocation(
                "ordinary.bin",
                ORDINARY_AAB_PATH,
                ORDINARY_APK_PATH,
                SEMANTIC_HASH,
            ),
        ),
        hardenedOwnedResources = mapOf(
            RESOURCE_KEY to OwnedResourceLocation(
                hardenedAabPath.substringAfterLast('/'),
                hardenedAabPath,
                hardenedApkPath,
                SEMANTIC_HASH,
            ),
        ),
    )

    private fun ownedDex(): ByteArray {
        val ownedClass = ImmutableClassDef(
            OWNED_DESCRIPTOR,
            AccessFlags.PUBLIC.value,
            "Ljava/lang/Object;",
            emptyList(),
            null,
            emptySet(),
            emptyList(),
            emptyList(),
        )
        val store = MemoryDataStore()
        DexPool.writeTo(store, ImmutableDexFile(Opcodes.getDefault(), listOf(ownedClass)))
        return store.data
    }

    private fun resourceTable(aabPath: String): ByteArray = Resources.ResourceTable.newBuilder()
        .addPackage(
            Resources.Package.newBuilder()
                .setPackageId(Resources.PackageId.newBuilder().setId(0x7f))
                .setPackageName("com.example.demo")
                .addType(
                    Resources.Type.newBuilder()
                        .setTypeId(Resources.TypeId.newBuilder().setId(0x12))
                        .setName("raw")
                        .addEntry(
                            Resources.Entry.newBuilder()
                                .setEntryId(Resources.EntryId.newBuilder().setId(1))
                                .setName("owned")
                                .addConfigValue(
                                    Resources.ConfigValue.newBuilder().setValue(
                                        Resources.Value.newBuilder().setItem(
                                            Resources.Item.newBuilder().setFile(
                                                Resources.FileReference.newBuilder().setPath(aabPath.removePrefix("base/")),
                                            ),
                                        ),
                                    ),
                                ),
                        ),
                ),
        )
        .build()
        .toByteArray()

    private fun artifact(path: Path, vararg entries: Pair<String, ByteArray>): Path = path.also {
        ZipOutputStream(path.outputStream()).use { output ->
            entries.forEach { (entryName, bytes) ->
                output.putNextEntry(ZipEntry(entryName))
                output.write(bytes)
                output.closeEntry()
            }
        }
    }

    private companion object {
        const val OWNED_DESCRIPTOR = "Lcom/example/demo/match/Owned;"
        val RESOURCE_KEY = OwnedResourceKey(0x7f120001, "")
        val RESOURCE_BYTES = "owned resource".toByteArray()
        const val ORDINARY_AAB_PATH = "base/res/raw/ordinary.bin"
        const val ORDINARY_APK_PATH = "res/raw/ordinary.bin"
        const val IDENTITY_AAB_PATH = "base/res/raw/identity.bin"
        const val IDENTITY_APK_PATH = "res/raw/identity.bin"
        const val ANALYSIS_AAB_PATH = "base/res/raw/analysis.bin"
        const val ANALYSIS_APK_PATH = "res/raw/analysis.bin"
        const val SEMANTIC_HASH = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val CONFIGURATION_SHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        const val LEGACY_CONFIGURATION_SHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        const val LEGACY_OWNERSHIP_SHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }
}
