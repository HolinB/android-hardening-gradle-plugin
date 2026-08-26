package com.holin.android.hardening.tasks

import com.holin.android.hardening.artifact.ArtifactPathBoundary
import com.holin.android.hardening.device.DeviceAcceptanceConfigurationResolver
import com.holin.android.hardening.device.DeviceAcceptanceRequest
import com.holin.android.hardening.device.DeviceAcceptanceRunner
import com.holin.android.hardening.similarity.HardeningBaselineCaptureRequest
import com.holin.android.hardening.similarity.HardeningBaselineExpectation
import com.holin.android.hardening.similarity.ImmutableHardeningBaselineStore
import com.holin.android.hardening.similarity.BaselineOwnedDescriptorAligner
import com.holin.android.hardening.similarity.OwnedArtifactAnalyzer
import com.holin.android.hardening.similarity.OwnedArtifactComparisonRunner
import com.holin.android.hardening.similarity.OwnedArtifactInventoryCodec
import com.holin.android.hardening.similarity.OwnedArtifactSimilarityScorerV1
import com.holin.android.hardening.similarity.SimilarityReportCodec
import com.holin.android.hardening.similarity.ValidatedOwnedArtifactInventories
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.HardeningStateLockService
import com.holin.android.hardening.state.PortableStateMigrationDescriptorLoader
import com.holin.android.hardening.state.StateStore
import java.io.File
import java.nio.file.Files
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault

@DisableCachingByDefault(because = "Baseline capture is an explicit immutable one-time operation")
abstract class CaptureHardeningBaselineTask : DefaultTask() {
    @get:Input abstract val projectKey: Property<String>
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val configurationSha256: Property<String>
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val ordinaryBundle: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val hardenedBundle: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val ordinaryUniversalApk: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val hardenedUniversalApk: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val ownedArtifactInventory: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val ownedArtifactAnalysisInventory: RegularFileProperty
    @get:Internal abstract val baselineRoot: DirectoryProperty
    @get:OutputDirectory
    val baselineParentDirectory: Provider<File>
        get() = baselineRoot.map { directory ->
            requireNotNull(directory.asFile.parentFile) { "hardening baseline root must have a parent directory" }
        }
    @get:Internal abstract val baselineDirectory: DirectoryProperty
    @get:Internal abstract val repositoryRoot: DirectoryProperty
    @get:Internal abstract val artifactBoundary: DirectoryProperty

    init { outputs.upToDateWhen { false } }

    @TaskAction
    fun capture() {
        val inputs = inputs()
        val inventories = ValidatedOwnedArtifactInventories(
            identity = OwnedArtifactInventoryCodec.decode(Files.readString(inputs.identityInventory)),
            analysis = OwnedArtifactInventoryCodec.decode(Files.readString(inputs.analysisInventory)),
        )
        val request = inventories.analysisRequest(
            inputs.ordinaryAab, inputs.hardenedAab, inputs.ordinaryApk, inputs.hardenedApk,
        )
        val (ordinary, hardened) = OwnedArtifactAnalyzer().analyzePair(request)
        val report = OwnedArtifactSimilarityScorerV1.compare(ordinary, hardened)
        val store = baselineStore()
        val captured = store.capture(
            HardeningBaselineCaptureRequest(
                projectKey.get(), variantName.get(), inputs.ordinaryAab, inputs.hardenedAab,
                inputs.ordinaryApk, inputs.hardenedApk, OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
                inventories.identityOwnershipSha256, configurationSha256.get(), report,
            ),
        )
        require(captured.root == baselineRoot.get().asFile.toPath().toAbsolutePath().normalize()) {
            "captured hardening baseline root differs from the declared task output"
        }
    }

    private fun baselineStore() = ImmutableHardeningBaselineStore(
        repositoryRoot.get().asFile.toPath(), baselineDirectory.get().asFile.toPath(),
    )

    private fun inputs(): SimilarityInputs {
        val boundary = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
        return SimilarityInputs(
            boundary.requireInput(ordinaryBundle.get().asFile.toPath()),
            boundary.requireInput(hardenedBundle.get().asFile.toPath()),
            boundary.requireInput(ordinaryUniversalApk.get().asFile.toPath()),
            boundary.requireInput(hardenedUniversalApk.get().asFile.toPath()),
            boundary.requireInput(ownedArtifactInventory.get().asFile.toPath()),
            boundary.requireInput(ownedArtifactAnalysisInventory.get().asFile.toPath()),
        )
    }
}

@DisableCachingByDefault(because = "Candidate artifacts are invocation-specific and relatively gated")
abstract class CompareHardeningSimilarityTask : DefaultTask() {
    @get:Input abstract val projectKey: Property<String>
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val configurationSha256: Property<String>
    @get:Input abstract val minimumImprovementPoints: Property<Double>
    @get:Input abstract val autoMigrateLegacyState: Property<Boolean>
    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val migrationDescriptor: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val ordinaryBundle: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val hardenedBundle: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val ordinaryUniversalApk: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val hardenedUniversalApk: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val ownedArtifactInventory: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val ownedArtifactAnalysisInventory: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val currentR8Mapping: RegularFileProperty
    @get:InputDirectory @get:PathSensitive(PathSensitivity.NONE) abstract val baselineRoot: DirectoryProperty
    @get:OutputFile abstract val jsonReport: RegularFileProperty
    @get:OutputFile abstract val markdownReport: RegularFileProperty
    @get:Internal abstract val baselineDirectory: DirectoryProperty
    @get:Internal abstract val repositoryRoot: DirectoryProperty
    @get:Internal abstract val mappingStoreDirectory: DirectoryProperty
    @get:Internal abstract val artifactBoundary: DirectoryProperty
    @get:Internal abstract val lockService: Property<HardeningStateLockService>

    init {
        autoMigrateLegacyState.convention(false)
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun compare() {
        val repository = repositoryRoot.get().asFile.toPath().toAbsolutePath().normalize()
        val projectKey = projectKey.get()
        val variant = variantName.get()
        val baselineStore = ImmutableHardeningBaselineStore(
            repository,
            baselineDirectory.get().asFile.toPath(),
        )
        if (autoMigrateLegacyState.get()) {
            lockService.get().withLock {
                val migration = PortableStateMigrationDescriptorLoader.load(
                    repository,
                    migrationDescriptor.get().asFile.toPath(),
                    projectKey,
                    variant,
                )
                migration.baseline?.let { baseline ->
                    baselineStore.migrateLegacyV1(
                        projectKey,
                        variant,
                        configurationSha256.get(),
                        baseline,
                    )
                }
            }
        }
        val boundary = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
        val inputs = SimilarityInputs(
            boundary.requireInput(ordinaryBundle.get().asFile.toPath()),
            boundary.requireInput(hardenedBundle.get().asFile.toPath()),
            boundary.requireInput(ordinaryUniversalApk.get().asFile.toPath()),
            boundary.requireInput(hardenedUniversalApk.get().asFile.toPath()),
            boundary.requireInput(ownedArtifactInventory.get().asFile.toPath()),
            boundary.requireInput(ownedArtifactAnalysisInventory.get().asFile.toPath()),
        )
        val inventories = ValidatedOwnedArtifactInventories(
            identity = OwnedArtifactInventoryCodec.decode(Files.readString(inputs.identityInventory)),
            analysis = OwnedArtifactInventoryCodec.decode(Files.readString(inputs.analysisInventory)),
        )
        val mappingStore = mappingStoreDirectory.get().asFile.toPath().toAbsolutePath().normalize()
        require(mappingStore.startsWith(repository) && mappingStore != repository) {
            "hardening mapping store must stay below the repository root"
        }
        val currentMapping = Files.readString(
            boundary.requireInput(currentR8Mapping.get().asFile.toPath()),
        )
        val stateRoot = mappingStore.resolve(projectKey).resolve(variant).normalize()
        val descriptorAligner = BaselineOwnedDescriptorAligner()
        OwnedArtifactComparisonRunner(
            baselineDescriptorAlignmentResolver = { baselineHardenedAab, currentDescriptors ->
                descriptorAligner.align(
                    StateStore().readArchivedMapping(
                        stateRoot,
                        projectKey,
                        variant,
                        Sha256.file(baselineHardenedAab),
                        true,
                    ),
                    currentMapping,
                    currentDescriptors,
                )
            },
        ).compare(
            baselineStore,
            HardeningBaselineExpectation(
                projectKey, variant, OwnedArtifactSimilarityScorerV1.SCORER_VERSION,
                inventories.identityOwnershipSha256, configurationSha256.get(),
            ),
            inventories.analysisRequest(
                inputs.ordinaryAab, inputs.hardenedAab, inputs.ordinaryApk, inputs.hardenedApk,
            ),
            minimumImprovementPoints.get(),
            boundary.prepareOutput(jsonReport.get().asFile.toPath()),
            boundary.prepareOutput(markdownReport.get().asFile.toPath()),
        )
    }
}

@DisableCachingByDefault(because = "Device acceptance is an explicit live-device operation")
abstract class SmokeHardeningTask : DefaultTask() {
    @get:Input abstract val deviceExecutionAuthorized: Property<Boolean>
    @get:Input @get:Optional abstract val serial: Property<String>
    @get:Input abstract val autoSelectSingleDevice: Property<Boolean>
    @get:Input @get:Optional abstract val applicationId: Property<String>
    @get:Input abstract val applicationIdFromVariant: Property<Boolean>
    @get:Input abstract val variantApplicationId: Property<String>
    @get:Input @get:Optional abstract val launchActivity: Property<String>
    @get:Input abstract val launchActivityFromManifest: Property<Boolean>
    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val mergedManifest: RegularFileProperty
    @get:Input abstract val stabilitySeconds: Property<Int>
    @get:Input abstract val runTaskName: Property<String>
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val hardenedUniversalApk: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val comparisonReport: RegularFileProperty
    @get:Internal abstract val sdkDirectory: DirectoryProperty
    @get:Internal abstract val artifactBoundary: DirectoryProperty

    init {
        deviceExecutionAuthorized.convention(false)
    }

    @TaskAction
    fun smoke() {
        check(deviceExecutionAuthorized.get()) {
            "device acceptance may only execute from ${runTaskName.orNull ?: "hardeningRun<Variant>"}"
        }
        require(stabilitySeconds.get() == 30) {
            "device acceptance stabilitySeconds must be 30 in v1"
        }
        val boundary = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
        val apk = boundary.requireInput(hardenedUniversalApk.get().asFile.toPath())
        val report = SimilarityReportCodec.decode(
            Files.readString(boundary.requireInput(comparisonReport.get().asFile.toPath())),
        )
        require(report.hardenedUniversalApkSha256 == Sha256.file(apk)) {
            "comparison report does not identify the smoke-test APK"
        }
        val resolvedApplicationId = DeviceAcceptanceConfigurationResolver.applicationId(
            applicationId.orNull,
            applicationIdFromVariant.get(),
            variantApplicationId.orNull,
        )
        val manifestXml = mergedManifest.orNull?.asFile?.toPath()?.let { manifest ->
            Files.readString(boundary.requireInput(manifest))
        }
        val resolvedLaunchActivity = DeviceAcceptanceConfigurationResolver.launchActivity(
            launchActivity.orNull,
            launchActivityFromManifest.get(),
            manifestXml,
            resolvedApplicationId,
        )
        DeviceAcceptanceRunner().smoke(
            DeviceAcceptanceRequest(
                sdkDirectory.get().asFile.toPath(), serial.orNull, autoSelectSingleDevice.get(),
                resolvedApplicationId, resolvedLaunchActivity, stabilitySeconds.get(), apk,
            ),
        )
    }
}

private data class SimilarityInputs(
    val ordinaryAab: java.nio.file.Path,
    val hardenedAab: java.nio.file.Path,
    val ordinaryApk: java.nio.file.Path,
    val hardenedApk: java.nio.file.Path,
    val identityInventory: java.nio.file.Path,
    val analysisInventory: java.nio.file.Path,
)
