package com.holin.android.hardening.tasks

import com.holin.android.hardening.artifact.BundleJarSigner
import com.holin.android.hardening.artifact.BundlePostRewriteSemanticVerifier
import com.holin.android.hardening.artifact.HardenedBundlePlanReportCodec
import com.holin.android.hardening.artifact.HardenedBundlePlanRequest
import com.holin.android.hardening.artifact.HardenedBundlePlanner
import com.holin.android.hardening.artifact.BundleRewriteManifestCodec
import com.holin.android.hardening.artifact.BundleSemanticVerificationResultCodec
import com.holin.android.hardening.artifact.BundleVerificationReport
import com.holin.android.hardening.artifact.BundleVerificationReportCodec
import com.holin.android.hardening.artifact.BundleZipRewriter
import com.holin.android.hardening.artifact.BundletoolBundleValidator
import com.holin.android.hardening.artifact.ArtifactPathBoundary
import com.holin.android.hardening.artifact.SignedBundleVerifier
import com.holin.android.hardening.artifact.SigningMaterial
import com.holin.android.hardening.state.AtomicFiles
import com.holin.android.hardening.state.InvocationSaltService
import com.holin.android.hardening.state.PreparedStateCodec
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.naming.RegistryCodec
import com.holin.android.hardening.similarity.OwnedArtifactInventoryCodec
import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.DependencyMetadataMode
import java.nio.file.Files
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault

@DisableCachingByDefault(because = "Each opted-in invocation has a fresh content salt")
abstract class RewriteHardeningBundleTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val inputBundle: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val r8Mapping: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val codeRegistry: RegularFileProperty

    @get:Input
    abstract val namespace: Property<String>

    @get:Input
    abstract val applicationId: Property<String>

    @get:Input
    abstract val minimumCodeCoverage: Property<Double>

    @get:Input
    abstract val minimumCodeSimHashDistance: Property<Int>

    @get:Input
    abstract val maximumDexGrowth: Property<Double>

    @get:Input
    abstract val enforceMaximumDexGrowth: Property<Boolean>

    @get:Input
    abstract val bitmapMode: Property<com.holin.android.hardening.resources.BitmapMode>

    @get:Input
    abstract val minimumImageCoverage: Property<Double>

    @get:Input
    abstract val minimumImageSsim: Property<Double>

    @get:Input
    abstract val minimumImagePHashDistance: Property<Int>

    @get:Input
    abstract val dependencyMetadata: Property<DependencyMetadataMode>

    @get:org.gradle.api.tasks.Optional @get:InputFile @get:PathSensitive(PathSensitivity.NONE)
    abstract val runtimeClosure: RegularFileProperty

    @get:org.gradle.api.tasks.Optional @get:InputFile @get:PathSensitive(PathSensitivity.NONE)
    abstract val dependencyTransformationReport: RegularFileProperty

    @get:org.gradle.api.tasks.InputFiles @get:PathSensitive(PathSensitivity.NONE)
    abstract val preR8RelocationPlans: org.gradle.api.file.ConfigurableFileCollection

    @get:Input abstract val nativeConfiguration: Property<String>

    @get:Input
    abstract val assetsConfiguration: Property<String>

    @get:org.gradle.api.tasks.InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val assetSourceFiles: org.gradle.api.file.ConfigurableFileCollection

    @get:Input
    abstract val valueResourcesConfiguration: Property<String>

    @get:Input
    abstract val structuralMetadataEntryCount: Property<Int>

    @get:OutputFile
    abstract val unsignedBundle: RegularFileProperty

    @get:OutputFile
    abstract val rewriteManifest: RegularFileProperty

    @get:OutputFile
    abstract val semanticResults: RegularFileProperty

    @get:OutputFile
    abstract val controlledTransformationReport: RegularFileProperty

    @get:OutputFile
    abstract val runtimeStringReport: RegularFileProperty

    @get:OutputFile
    abstract val categoryReport: RegularFileProperty

    @get:OutputFile
    abstract val planReport: RegularFileProperty

    @get:OutputFile
    abstract val ownedArtifactInventory: RegularFileProperty

    @get:OutputFile
    abstract val ownedArtifactAnalysisInventory: RegularFileProperty

    @get:Internal
    abstract val artifactBoundary: DirectoryProperty

    @get:Internal
    abstract val repositoryRoot: DirectoryProperty

    @get:Internal
    abstract val ownership: Property<HardeningOwnership>
    @get:Input
    abstract val applicationModulePath: Property<String>

    @get:Internal
    abstract val preparedDirectory: DirectoryProperty

    @get:Internal
    abstract val saltService: Property<InvocationSaltService>

    init {
        valueResourcesConfiguration.convention(com.holin.android.hardening.resources.ValueResourcePolicy().encode())
        nativeConfiguration.convention(com.holin.android.hardening.nativecode.NativePolicy().encode())
        assetsConfiguration.convention(com.holin.android.hardening.resources.AssetPolicy().encode())
        bitmapMode.convention(com.holin.android.hardening.resources.BitmapMode.LEGACY_PERCEPTUAL)
        applicationId.convention(namespace)
        controlledTransformationReport.convention(project.layout.buildDirectory.file("reports/hardening/$name/controlled-transformations.json"))
        runtimeStringReport.convention(project.layout.buildDirectory.file("reports/hardening/$name/runtime-strings-final.json"))
        categoryReport.convention(project.layout.buildDirectory.file("reports/hardening/$name/category-report.json"))
        outputs.upToDateWhen { false }
    }

    private fun dependencyResult(mapping: String): Any {
        if (!dependencyTransformationReport.isPresent) return mapOf("enabled" to false)
        val report = groovy.json.JsonSlurper().parseText(dependencyTransformationReport.get().asFile.readText()) as Map<*, *>
        val names = mapping.lineSequence().filter { it.isNotBlank() && !it.startsWith('#') && !it.startsWith(' ') && " -> " in it }.map { it.substringBefore(" -> ") }.toSet()
        val rows = (report["entries"] as List<*>).map { value ->
            val row = value as Map<*, *>
            val relocated = row["relocatedClasses"] as? Map<*, *> ?: emptyMap<String, String>()
            val survivors = relocated.keys.filter { it.toString().replace('/', '.') in names }
            row + mapOf("sourceIdentitiesInFinalMapping" to survivors, "mappedSourceCount" to survivors.size,
                "effectiveClassRenameCount" to if (survivors.isEmpty()) 0 else null,
                "finalDexBenefit" to if (survivors.isEmpty()) "NO_SURVIVING_SOURCE_CLASS_MAPPING_DO_NOT_CREDIT_RENAME" else "MAPPING_MAY_INCLUDE_INLINED_CLASSES_MEASURE_DEX_SEPARATELY")
        }
        return report + mapOf("entries" to rows)
    }

    @TaskAction
    fun rewrite() {
        val paths = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
        val input = paths.requireInput(inputBundle.get().asFile.toPath())
        val mapping = paths.requireInput(r8Mapping.get().asFile.toPath())
        val output = paths.prepareOutput(unsignedBundle.get().asFile.toPath())
        val manifestOutput = paths.prepareOutput(rewriteManifest.get().asFile.toPath())
        val semanticOutput = paths.prepareOutput(semanticResults.get().asFile.toPath())
        val reportOutput = paths.prepareOutput(planReport.get().asFile.toPath())
        val inventoryOutput = paths.prepareOutput(ownedArtifactInventory.get().asFile.toPath())
        val analysisInventoryOutput = paths.prepareOutput(ownedArtifactAnalysisInventory.get().asFile.toPath())
        require(inventoryOutput != analysisInventoryOutput) {
            "identity and analysis owned artifact inventory outputs must be distinct"
        }
        val preparedRoot = preparedDirectory.get().asFile.toPath().toAbsolutePath().normalize()
        val preparedStatePath = paths.requireInput(preparedRoot.resolve(PREPARED_STATE_FILE))
        val seedPath = paths.requireInput(preparedRoot.resolve("seed.bin"))
        val preparedRegistryPath = paths.requireInput(preparedRoot.resolve("registry.json"))
        val registryInput = if (codeRegistry.isPresent) {
            paths.requireInput(codeRegistry.get().asFile.toPath())
        } else {
            preparedRegistryPath
        }
        val preparedMappingPath = paths.requireInput(preparedRoot.resolve("mapping.txt"))
        val preparedState = PreparedStateCodec.read(preparedStatePath)
        require(preparedState.preparedDirectory.toAbsolutePath().normalize() == preparedRoot) {
            "prepared state directory does not match the rewrite task handoff"
        }
        require(preparedState.coordinates.namespace == namespace.get()) {
            "prepared state namespace differs from the selected variant"
        }
        require(preparedState.coordinates.applicationId == applicationId.get()) {
            "prepared state application ID differs from the selected variant"
        }
        require(preparedState.contentSaltSha256 == saltService.get().sha256()) {
            "prepared state belongs to a different hardening invocation"
        }
        val registryCodec = RegistryCodec()
        val registry = registryCodec.decode(Files.readString(registryInput))
        require(registry.seedSha256 == preparedState.identity.seedHash) {
            "code registry belongs to another lineage"
        }
        require(registry.generation == preparedState.identity.generation) {
            "code registry generation differs from prepared state"
        }
        val lineageSeed = Files.readAllBytes(seedPath)
        val mappingText = Files.readString(mapping)
        fun writeRuntimeStrings(diagnostic: Map<String, Any>) {
            Files.writeString(paths.prepareOutput(runtimeStringReport.get().asFile.toPath()),
                groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(diagnostic + mapOf(
                    "variant" to preparedState.coordinates.variant, "inputFingerprint" to Sha256.hex((Sha256.file(input) + ":" +
                        (runtimeClosure.orNull?.asFile?.toPath()?.let(Sha256::file) ?: "disabled")).toByteArray(Charsets.UTF_8))))))
        }
        val plan = try {
            saltService.get().withSalt { salt ->
                HardenedBundlePlanner().plan(
                    HardenedBundlePlanRequest(
                        input,
                        repositoryRoot.get().asFile.toPath(),
                        mappingText,
                        namespace.get(),
                        applicationId.get(),
                        lineageSeed,
                        registry,
                        preparedState.identity.generation,
                        salt,
                        minimumCodeCoverage.get(),
                        minimumCodeSimHashDistance.get(),
                        maximumDexGrowth.get(),
                        enforceMaximumDexGrowth.get(),
                        minimumImageCoverage.get(),
                        minimumImageSsim.get(),
                        minimumImagePHashDistance.get(),
                        applicationModulePath.get(),
                        ownership.get(),
                        preparedState.identity.fixedSeedSha256 != null,
                        preparedState.identity.fixedSeedSha256,
                        dependencyMetadata.get(),
                        structuralMetadataEntryCount.get(),
                        com.holin.android.hardening.resources.ValueResourcePolicy.decode(valueResourcesConfiguration.get()),
                        bitmapMode.get(),
                        com.holin.android.hardening.resources.AssetPolicy.decode(assetsConfiguration.get()),
                        runtimeClosure.orNull?.asFile?.readText()?.let(com.holin.android.hardening.runtime.RuntimeClosure::read),
                        com.holin.android.hardening.nativecode.NativePolicy.decode(nativeConfiguration.get()),
                        preR8RelocationPlans.files.sortedBy { it.path }.flatMap {
                            com.holin.android.hardening.components.PreR8Relocation.readPlan(it.readText()).entries
                        }.associate { it.toPair() },
                    ),
                )
            }
        } catch (failure: com.holin.android.hardening.runtime.RuntimeStringCoverageException) {
            writeRuntimeStrings(failure.diagnostic)
            throw org.gradle.api.GradleException("${failure.message}; report: ${runtimeStringReport.get().asFile}", failure)
        } finally {
            lineageSeed.fill(0)
        }
        @Suppress("UNCHECKED_CAST")
        val stringDiagnostic = plan.controlledTransformations["runtimeStrings"] as? Map<String, Any> ?: mapOf("enabled" to false)
        writeRuntimeStrings(stringDiagnostic)
        val runtimePolicy = runtimeClosure.orNull?.asFile?.readText()?.let(com.holin.android.hardening.runtime.RuntimeClosure::read)?.policy
        if (runtimePolicy != null) {
            val entries = stringDiagnostic["entries"] as? List<*> ?: emptyList<Any>()
            val skipped = entries.filterIsInstance<Map<*, *>>().filter { it["group"] == "candidate" && it["transformed"] != true }
            if (skipped.isNotEmpty()) logger.warn("{} candidate runtime strings remain unprotected; report: {}", skipped.size, runtimeStringReport.get().asFile)
        }
        require(plan.report.sourceAabSha256 == Sha256.file(input)) {
            "bundle hardening plan does not identify the ordinary AAB"
        }
        require(plan.report.contentSaltSha256 == saltService.get().sha256()) {
            "bundle hardening plan belongs to a different invocation"
        }
        require(
            plan.report.fixedSeedProvided == (preparedState.identity.fixedSeedSha256 != null) &&
                plan.report.fixedSeedHash == preparedState.identity.fixedSeedSha256,
        ) {
            "bundle hardening plan has a different reproducibility identity"
        }
        commitRegistryAfterVerification(
            preparedRegistryPath,
            registryCodec.encode(plan.updatedRegistry).toByteArray(Charsets.UTF_8),
        ) {
            val rewrite = BundleZipRewriter().rewrite(
                input,
                output,
                saltService.get().sha256(),
                plan.replacements,
                plan.removals,
                plan.additions,
            )
            require(rewrite.originalAabSha256 == plan.report.sourceAabSha256) {
                "bundle rewrite source differs from its transformation plan"
            }
            val semanticResults = saltService.get().withSalt { contentSalt ->
                BundlePostRewriteSemanticVerifier().verify(
                    input,
                    output,
                    rewrite.manifest,
                    plan.report,
                    contentSalt,
                    plan.dexVerificationScope,
                    plan.runtimeVerificationScope,
                )
            }
            AtomicFiles().replace(
                paths.prepareOutput(categoryReport.get().asFile.toPath()),
                com.holin.android.hardening.similarity.CategoryArtifactReport.compare(input, output).toByteArray(Charsets.UTF_8),
            )
            AtomicFiles().replace(
                paths.prepareOutput(controlledTransformationReport.get().asFile.toPath()),
                groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(plan.controlledTransformations + mapOf("dependencies" to dependencyResult(mappingText)))).toByteArray(Charsets.UTF_8),
            )
            BundleRewriteManifestCodec.write(manifestOutput, rewrite.manifest)
            BundleSemanticVerificationResultCodec.write(semanticOutput, semanticResults)
            AtomicFiles().replace(
                reportOutput,
                HardenedBundlePlanReportCodec.encode(plan.report).toByteArray(Charsets.UTF_8),
            )
            AtomicFiles().replace(
                inventoryOutput,
                OwnedArtifactInventoryCodec.encode(plan.ownedArtifactInventory).toByteArray(Charsets.UTF_8),
            )
            AtomicFiles().replace(
                analysisInventoryOutput,
                OwnedArtifactInventoryCodec.encode(plan.ownedArtifactAnalysisInventory).toByteArray(Charsets.UTF_8),
            )
            AtomicFiles().replace(preparedMappingPath, mappingText.toByteArray(Charsets.UTF_8))
            paths.requireInput(output)
            paths.requireInput(manifestOutput)
            paths.requireInput(semanticOutput)
            paths.requireInput(reportOutput)
            paths.requireInput(inventoryOutput)
            paths.requireInput(analysisInventoryOutput)
        }
    }
}

internal fun <T> commitRegistryAfterVerification(
    preparedRegistry: java.nio.file.Path,
    updatedRegistry: ByteArray,
    verifiedRewrite: () -> T,
): T {
    val result = verifiedRewrite()
    AtomicFiles().replace(preparedRegistry, updatedRegistry)
    return result
}

@DisableCachingByDefault(because = "Signing material is deliberately excluded from Gradle fingerprints")
abstract class SignHardeningBundleTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val unsignedBundle: RegularFileProperty

    @get:OutputFile
    abstract val signedCandidate: RegularFileProperty

    @get:Internal
    abstract val artifactBoundary: DirectoryProperty

    private lateinit var signingMaterial: SigningMaterial

    init {
        outputs.upToDateWhen { false }
        notCompatibleWithConfigurationCache("hardening signing credentials must remain invocation-local")
    }

    internal fun useSigningMaterial(material: SigningMaterial) {
        check(!::signingMaterial.isInitialized) { "hardening signing material was configured twice" }
        signingMaterial = material
    }

    @TaskAction
    fun sign() {
        check(::signingMaterial.isInitialized) { "hardening signing material was not configured" }
        val paths = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
        val input = paths.requireInput(unsignedBundle.get().asFile.toPath())
        val output = paths.prepareOutput(signedCandidate.get().asFile.toPath())
        BundleJarSigner().sign(
            unsignedBundle = input,
            signedBundle = output,
            material = signingMaterial,
        )
        paths.requireInput(output)
    }
}

@DisableCachingByDefault(because = "Validation atomically publishes a per-invocation signed artifact")
abstract class ValidateHardeningBundleTask : DefaultTask() {
    @get:Input
    abstract val variantName: Property<String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val ordinaryBundle: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val signedCandidate: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val rewriteManifest: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val semanticResults: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val transformationReport: RegularFileProperty

    @get:OutputFile
    abstract val hardenedBundle: RegularFileProperty

    @get:OutputFile
    abstract val verificationReport: RegularFileProperty

    @get:Internal
    abstract val artifactBoundary: DirectoryProperty

    @get:Internal
    abstract val saltService: Property<InvocationSaltService>

    init {
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun validateAndPublish() {
        val paths = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
        val ordinary = paths.requireInput(ordinaryBundle.get().asFile.toPath())
        val candidate = paths.requireInput(signedCandidate.get().asFile.toPath())
        val manifest = BundleRewriteManifestCodec.read(paths.requireInput(rewriteManifest.get().asFile.toPath()))
        val semanticVerificationResults = BundleSemanticVerificationResultCodec.read(
            paths.requireInput(semanticResults.get().asFile.toPath()),
        )
        val transformation = HardenedBundlePlanReportCodec.decode(
            Files.readString(paths.requireInput(transformationReport.get().asFile.toPath())),
        )
        require(transformation.sourceAabSha256 == Sha256.file(ordinary)) {
            "transformation report does not identify the ordinary AAB"
        }
        require(transformation.contentSaltSha256 == saltService.get().sha256()) {
            "transformation report belongs to a different invocation"
        }
        val fixedSeedHash = saltService.get().stateReproducibility().fixedSeedSha256
        require(
            transformation.fixedSeedProvided == (fixedSeedHash != null) &&
                transformation.fixedSeedHash == fixedSeedHash,
        ) {
            "transformation report has a different reproducibility identity"
        }
        val output = paths.prepareOutput(hardenedBundle.get().asFile.toPath())
        val reportOutput = paths.prepareOutput(verificationReport.get().asFile.toPath())
        val report = SignedBundleVerifier(BundletoolBundleValidator::validate).verifyAndPublish(
            ordinaryBundle = ordinary,
            signedCandidate = candidate,
            outputBundle = output,
            contentSaltSha256 = saltService.get().sha256(),
            rewriteManifest = manifest,
            semanticResults = semanticVerificationResults,
        )
        paths.requireInput(output)
        val json = BundleVerificationReportCodec.encode(
            BundleVerificationReport(
                variantName.get(),
                saltService.get().sha256(),
                report.originalAabSha256,
                report.hardenedAabSha256,
                report.hardenedSignerCertificateSha256,
                report.preservedEntryCount,
                true,
                transformation.fixedSeedProvided,
                transformation.fixedSeedHash,
            ),
        )
        AtomicFiles().replace(reportOutput, json.toByteArray(Charsets.UTF_8))
        paths.requireInput(reportOutput)
    }
}
