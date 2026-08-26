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
        val fixedSeedSha256 = extension.reproducibility.fixedSeed.orNull
            ?.let(FixedSeedDerivation::seedSha256)
        append(if (fixedSeedSha256 == null) "owned-similarity-config-v4\n" else "owned-similarity-config-v5\n")
        field("projectKey", extension.projectKey.get())
        field("variant", variant)
        field("namespace", namespace)
        field("applicationId", applicationId)
        field("versionCode", versionCode)
        field("versionName", versionName)
        field("signingCertificateSha256", signingCertificateSha256)
        field("mapping.reusePrevious", extension.mapping.reusePrevious.get())
        field("mapping.missingPolicy", extension.mapping.missingPolicy.get().name)
        field("mapping.keepHistory", extension.mapping.keepHistory.get())
        field("mapping.quarantineInvalid", extension.mapping.quarantineInvalid.get())
        if (fixedSeedSha256 != null) {
            field("reproducibility.fixedSeedPresent", true)
            field("reproducibility.fixedSeedSha256", fixedSeedSha256)
        }
        field("naming.strategy", extension.naming.strategy.get().name)
        field("naming.renamePackages", extension.naming.renamePackages.get())
        field("naming.reuseAcrossBuilds", extension.naming.reuseAcrossBuilds.get())
        field("code.engine", extension.code.engine.get().name)
        field("code.preserveLineNumbers", extension.code.preserveLineNumbers.get())
        field("code.sourceFileMode", extension.code.sourceFileMode.get().name)
        field("code.stringFog", extension.code.stringFog.get().name)
        field("code.diversification.mode", extension.code.diversification.mode.get().name)
        field("code.diversification.contentSalt", extension.code.diversification.contentSalt.get().name)
        field("code.diversification.minimumCoverage", extension.code.diversification.minimumCoverage.get())
        field("code.diversification.minimumSimHashDistance", extension.code.diversification.minimumSimHashDistance.get())
        field("code.diversification.maximumGrowth", extension.code.diversification.maximumGrowth.get())
        field("code.diversification.enforceMaximumGrowth", extension.code.diversification.enforceMaximumGrowth.get())
        field("resources.mode", extension.resources.mode.get().name)
        field("resources.renameLayouts", extension.resources.renameLayouts.get())
        field("resources.renameDrawables", extension.resources.renameDrawables.get())
        field("resources.renameStyles", extension.resources.renameStyles.get())
        field("resources.preserveResourceIds", extension.resources.preserveResourceIds.get())
        field("resources.reuseNamesAcrossBuilds", extension.resources.reuseNamesAcrossBuilds.get())
        field("resources.styleHashPolicy", extension.resources.styleHashPolicy.get().name)
        field("resources.bitmapDiversification.safeOnly", extension.resources.bitmapDiversification.safeOnly.get())
        field("resources.bitmapDiversification.minimumCoverage", extension.resources.bitmapDiversification.minimumCoverage.get())
        field("resources.bitmapDiversification.minimumSsim", extension.resources.bitmapDiversification.minimumSsim.get())
        field(
            "resources.bitmapDiversification.minimumPHashDistance",
            extension.resources.bitmapDiversification.minimumPHashDistance.get(),
        )
        field("contracts.unresolvedAppReflection", extension.contracts.unresolvedAppReflection.get().name)
        field("contracts.unresolvedResourceLookup", extension.contracts.unresolvedResourceLookup.get().name)
        field("contracts.externalNames", extension.contracts.externalNames.get().name)
        field("signing.reuseVariantSigningConfig", extension.signing.reuseVariantSigningConfig.get())
        field("similarity.mode", extension.similarity.mode.get().name)
        field("similarity.minimumImprovementPoints", extension.similarity.minimumImprovementPoints.get())
        field("similarity.enforceRelativeImprovement", extension.similarity.enforceRelativeImprovement.get())
        field("similarity.maximumOverallExclusive", extension.similarity.maximumOverallExclusive.get())
        field("similarity.enforceMaximumOverall", extension.similarity.enforceMaximumOverall.get())
        field("similarity.maximumAabGrowth", extension.similarity.maximumAabGrowth.get())
        field("similarity.enforceMaximumAabGrowth", extension.similarity.enforceMaximumAabGrowth.get())
        field("legacyPlugins.mode", extension.legacyPlugins.mode.get().name)
        field("legacyPlugins.verifyCompatibility", extension.legacyPlugins.verifyCompatibility.get())
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
        ownership?.let { resolved ->
            field(
                "ownedSourceRoots",
                resolved.modules.sortedBy(HardeningOwnership.OwnedModule::path).joinToString(";") { module ->
                    listOf(
                        "java=${relativePaths(module, module.sourceRoots.javaDirectories)}",
                        "kotlin=${relativePaths(module, module.sourceRoots.kotlinDirectories)}",
                        "res=${relativePaths(module, module.sourceRoots.resourceDirectories)}",
                        "manifest=${relativePaths(module, module.sourceRoots.manifestFiles)}",
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
