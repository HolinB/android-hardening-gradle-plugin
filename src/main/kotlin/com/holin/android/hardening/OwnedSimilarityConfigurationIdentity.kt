package com.holin.android.hardening

import com.holin.android.hardening.artifact.BUNDLETOOL_VERSION
import com.holin.android.hardening.audit.LegacyPluginDeclarationCodec
import com.holin.android.hardening.similarity.OwnedArtifactSimilarityScorerV1
import com.holin.android.hardening.state.FixedSeedDerivation
import com.holin.android.hardening.state.Sha256

internal object OwnedSimilarityConfigurationIdentity {
    fun sha256(
        extension: AndroidHardeningExtension,
        variant: String,
        namespace: String,
        applicationId: String,
        versionCode: Int,
        versionName: String,
        signingCertificateSha256: String,
        ownership: HardeningOwnership? = null,
        legacyPlugins: List<LegacyPluginDeclaration>,
        legacyBaselineSha256: String,
    ): String = Sha256.hex(
        canonicalText(
            extension,
            variant,
            namespace,
            applicationId,
            versionCode,
            versionName,
            signingCertificateSha256,
            ownership,
            legacyPlugins,
            legacyBaselineSha256,
        ).toByteArray(Charsets.UTF_8),
    )

    internal fun canonicalText(
        extension: AndroidHardeningExtension,
        variant: String,
        namespace: String,
        applicationId: String,
        versionCode: Int,
        versionName: String,
        signingCertificateSha256: String,
        ownership: HardeningOwnership?,
        legacyPlugins: List<LegacyPluginDeclaration>,
        legacyBaselineSha256: String,
    ): String = buildString {
        require(versionName.isNotBlank() && '\n' !in versionName && '\r' !in versionName) {
            "versionName must be a nonblank single-line value"
        }
        require(SHA_256.matches(signingCertificateSha256)) {
            "signingCertificateSha256 must be lowercase SHA-256"
        }
        require(SHA_256.matches(legacyBaselineSha256)) {
            "legacyBaselineSha256 must be lowercase SHA-256"
        }
        val fixedSeedSha256 = extension.effectiveFixedSeed.orNull
            ?.let(FixedSeedDerivation::seedSha256)
        append("owned-similarity-config-v6\n")
        field("projectKey", extension.projectKey.get())
        field("variant", variant)
        field("namespace", namespace)
        field("applicationId", applicationId)
        field("versionCode", versionCode)
        field("versionName", versionName)
        field("signingCertificateSha256", signingCertificateSha256)
        field("mapping.reusePrevious", HardeningV1Policy.mappingReusePrevious)
        field("mapping.missingPolicy", HardeningV1Policy.mappingMissingPolicy.name)
        field("mapping.keepHistory", HardeningV1Policy.mappingKeepHistory)
        field("mapping.quarantineInvalid", HardeningV1Policy.mappingQuarantineInvalid)
        if (fixedSeedSha256 != null) {
            field("reproducibility.fixedSeedPresent", true)
            field("reproducibility.fixedSeedSha256", fixedSeedSha256)
        }
        field("naming.strategy", HardeningV1Policy.namingStrategy.name)
        field("naming.renamePackages", HardeningV1Policy.namingRenamePackages)
        field("naming.reuseAcrossBuilds", HardeningV1Policy.namingReuseAcrossBuilds)
        field("code.engine", HardeningV1Policy.codeEngine.name)
        field("code.preserveLineNumbers", HardeningV1Policy.codePreserveLineNumbers)
        field("code.sourceFileMode", HardeningV1Policy.codeSourceFileMode.name)
        field("code.stringFog", HardeningV1Policy.codeStringFog.name)
        field("code.diversification.mode", HardeningV1Policy.codeDiversificationMode.name)
        field("code.diversification.contentSalt", HardeningV1Policy.codeContentSalt.name)
        field("code.diversification.minimumCoverage", extension.code.diversification.minimumCoverage.get())
        field("code.diversification.minimumSimHashDistance", extension.code.diversification.minimumSimHashDistance.get())
        field("code.diversification.maximumGrowth", extension.code.diversification.maximumGrowth.get())
        field("code.diversification.enforceMaximumGrowth", extension.code.diversification.enforceMaximumGrowth.get())
        if (extension.dependencies.policy() != com.holin.android.hardening.dependencies.DependencyPolicy()) {
            field("dependencies", extension.dependencies.policy().encode())
        }
        if (extension.nativeLibraries.policy() != com.holin.android.hardening.nativecode.NativePolicy()) {
            field("nativeLibraries", extension.nativeLibraries.policy().encode())
        }
        if (extension.runtimeProtection.policy().enabled) {
            field("runtimeProtection", extension.runtimeProtection.policy().encode())
        }
        if (extension.components.policy() != com.holin.android.hardening.components.ComponentPolicy()) {
            field("components", extension.components.policy().encode())
        }
        if (extension.assets.policy() != com.holin.android.hardening.resources.AssetPolicy()) {
            field("assets", extension.assets.policy().encode())
        }
        if (extension.resources.values.policy() != com.holin.android.hardening.resources.ValueResourcePolicy()) {
            field("resources.values", extension.resources.values.policy().encode())
        }
        field("resources.mode", HardeningV1Policy.resourceMode.name)
        field("resources.renameLayouts", HardeningV1Policy.resourceRenameLayouts)
        field("resources.renameDrawables", HardeningV1Policy.resourceRenameDrawables)
        field("resources.renameStyles", HardeningV1Policy.resourceRenameStyles)
        field("resources.preserveResourceIds", HardeningV1Policy.resourcePreserveIds)
        field("resources.reuseNamesAcrossBuilds", HardeningV1Policy.resourceReuseNamesAcrossBuilds)
        field("resources.styleHashPolicy", HardeningV1Policy.resourceStyleHashPolicy.name)
        if (extension.resources.bitmapDiversification.mode.get() != com.holin.android.hardening.resources.BitmapMode.LEGACY_PERCEPTUAL) {
            field("resources.bitmapDiversification.mode", extension.resources.bitmapDiversification.mode.get().name)
        }
        field("resources.bitmapDiversification.safeOnly", HardeningV1Policy.bitmapSafeOnly)
        field("resources.bitmapDiversification.minimumCoverage", extension.resources.bitmapDiversification.minimumCoverage.get())
        field("resources.bitmapDiversification.minimumSsim", extension.resources.bitmapDiversification.minimumSsim.get())
        field(
            "resources.bitmapDiversification.minimumPHashDistance",
            extension.resources.bitmapDiversification.minimumPHashDistance.get(),
        )
        if (extension.verification.debuggableApkVariants.get().isNotEmpty()) {
            field("verification.debuggableApkVariants", extension.verification.debuggableApkVariants.get().sorted().joinToString(","))
        }
        field("bundle.dependencyMetadata", extension.bundle.dependencyMetadata.get().name)
        field("bundle.structuralMetadataEntryCount", extension.bundle.structuralMetadataEntryCount.get())
        field("contracts.unresolvedAppReflection", HardeningV1Policy.unresolvedAppReflection.name)
        field("contracts.unresolvedResourceLookup", HardeningV1Policy.unresolvedResourceLookup.name)
        field("contracts.externalNames", HardeningV1Policy.externalNames.name)
        field("signing.reuseVariantSigningConfig", HardeningV1Policy.reuseVariantSigningConfig)
        field("similarity.mode", HardeningV1Policy.similarityMode.name)
        field("similarity.minimumImprovementPoints", extension.similarity.minimumImprovementPoints.get())
        field("similarity.enforceRelativeImprovement", HardeningV1Policy.enforceRelativeImprovement)
        field("similarity.maximumOverallExclusive", extension.similarity.maximumOverallExclusive.get())
        field("similarity.enforceMaximumOverall", HardeningV1Policy.enforceMaximumOverall)
        field("similarity.maximumAabGrowth", extension.similarity.maximumAabGrowth.get())
        field("similarity.enforceMaximumAabGrowth", HardeningV1Policy.enforceMaximumAabGrowth)
        field("legacyPlugins.mode", HardeningV1Policy.legacyPluginMode.name)
        field("legacyPlugins.verifyCompatibility", HardeningV1Policy.verifyLegacyPluginCompatibility)
        field("legacyPlugins.baselineSha256", legacyBaselineSha256)
        field(
            "legacyPlugins.declarations",
            legacyPlugins.map(LegacyPluginDeclarationCodec::encode).sorted().joinToString(";"),
        )
        val declaredOwnership = ownership?.modules?.associate { module -> module.path to module.sourceSets }
            ?: extension.ownership.modules.get()
        field("ownedModules", declaredOwnership.keys.sorted().joinToString(","))
        field("ownedSourceSets", declaredOwnership.entries.sortedBy { it.key }.joinToString(";") { module ->
            "${module.key}:${module.value.sorted().joinToString(",")}"
        })
        val declaredImageIncludes = ownership?.modules?.associate { it.path to it.images.includes }
            ?: extension.ownership.declaredImageIncludes()
        val declaredImageExcludes = ownership?.modules?.associate { it.path to it.images.excludes }
            ?: extension.ownership.declaredImageExcludes()
        val declaredImageFormats = ownership?.modules?.associate { it.path to it.images.formats.map(ImageFormat::name).toSet() }
            ?: extension.ownership.declaredImageFormats().mapValues { (_, formats) -> formats.map(ImageFormat::name).toSet() }
        field("ownedImageIncludes", declaredImageIncludes.entries.sortedBy { it.key }.joinToString(";") {
            "${it.key}:${it.value.sorted().joinToString(",")}"
        })
        field("ownedImageExcludes", declaredImageExcludes.entries.sortedBy { it.key }.joinToString(";") {
            "${it.key}:${it.value.sorted().joinToString(",")}"
        })
        field("ownedImageFormats", declaredImageFormats.entries.sortedBy { it.key }.joinToString(";") {
            "${it.key}:${it.value.sorted().joinToString(",")}"
        })
        ownership?.let { resolved ->
            field(
                "ownedSourceRoots",
                resolved.modules.sortedBy(HardeningOwnership.OwnedModule::path).joinToString(";") { module ->
                    listOf(
                        "java=${relativePaths(module, module.sourceRoots.javaDirectories)}",
                        "kotlin=${relativePaths(module, module.sourceRoots.kotlinDirectories)}",
                        "res=${relativePaths(module, module.sourceRoots.resourceDirectories)}",
                        "manifest=${relativePaths(module, module.sourceRoots.manifestFiles)}",
                        "assets=${relativePaths(module, module.sourceRoots.assetDirectories)}",
                    ).joinToString(",", "${module.path}[", "]")
                },
            )
            field(
                "ownedWebpIncludes",
                resolved.modules.sortedBy(HardeningOwnership.OwnedModule::path).joinToString(";") { module ->
                    "${module.path}:${module.webp.includes.sorted().joinToString(",")}"
                },
            )
            field(
                "ownedWebpExcludes",
                resolved.modules.sortedBy(HardeningOwnership.OwnedModule::path).joinToString(";") { module ->
                    "${module.path}:${module.webp.excludes.sorted().joinToString(",")}"
                },
            )
            field("hardcodedReferenceKinds", resolved.hardcodedReferences.kinds.map(HardcodedReferenceKind::name).sorted().joinToString(","))
            field("hardcodedReferenceIncludes", resolved.hardcodedReferences.includeGlobs.sorted().joinToString(","))
            field("hardcodedReferenceExcludes", resolved.hardcodedReferences.excludeGlobs.sorted().joinToString(","))
            field("hardcodedReferenceFailOnUnresolved", resolved.hardcodedReferences.failOnUnresolvedOwnedReference.toString())
        }
        field(
            "generatedPackagePrefixes",
            (ownership?.generatedPackagePrefixes ?: extension.ownership.generatedPackagePrefixes.get()).sorted().joinToString(","),
        )
        field(
            "excludedPackagePrefixes",
            (ownership?.excludedPackagePrefixes ?: extension.ownership.excludedPackagePrefixes.get()).sorted().joinToString(","),
        )
        field("similarityScorerVersion", OwnedArtifactSimilarityScorerV1.SCORER_VERSION)
        field("bundletoolVersion", BUNDLETOOL_VERSION)
        field("apkMode", "UNIVERSAL")
    }

    private fun StringBuilder.field(name: String, value: Any) {
        append(name).append('=').append(value).append('\n')
    }

    private fun relativePaths(module: HardeningOwnership.OwnedModule, paths: Set<java.nio.file.Path>): String =
        paths.map { path -> module.directory.relativize(path).toString().replace('\\', '/') }
            .sorted()
            .joinToString("|")

    private val SHA_256 = Regex("[0-9a-f]{64}")
}
