package com.holin.android.hardening

/**
 * The v1 invariants that are part of the plugin contract rather than consumer input.
 *
 * The matching extension properties remain available for one compatibility cycle so
 * old builds can be validated. Task wiring uses these values directly, which keeps a
 * deprecated property from changing the implementation after it has passed validation.
 */
internal object HardeningV1Policy {
    const val mappingReusePrevious = true
    val mappingMissingPolicy: MissingPolicy = MissingPolicy.RECREATE
    const val mappingKeepHistory = true
    const val mappingQuarantineInvalid = true

    val namingStrategy: NamingStrategy = NamingStrategy.TYPED_PSEUDOWORDS
    const val namingRenamePackages = true
    const val namingReuseAcrossBuilds = true

    val codeEngine: CodeEngine = CodeEngine.R8
    const val codePreserveLineNumbers = true
    val codeSourceFileMode: SourceFileMode = SourceFileMode.PSEUDONYMIZE
    val codeStringFog: StringFogMode = StringFogMode.PRESERVE_CURRENT
    val codeDiversificationMode: DiversificationMode = DiversificationMode.DEX
    val codeContentSalt: ContentSaltMode = ContentSaltMode.FRESH_PER_BUILD

    val resourceMode: ResourceMode = ResourceMode.RENAME_AND_AUDIT
    const val resourceRenameLayouts = true
    const val resourceRenameDrawables = true
    const val resourceRenameStyles = true
    const val resourcePreserveIds = true
    const val resourceReuseNamesAcrossBuilds = true
    val resourceStyleHashPolicy: StyleHashPolicy = StyleHashPolicy.RESOURCE_TABLE_ONLY
    const val bitmapSafeOnly = true

    val unresolvedAppReflection: UnresolvedContractPolicy = UnresolvedContractPolicy.FAIL_BUILD
    val unresolvedResourceLookup: UnresolvedContractPolicy = UnresolvedContractPolicy.FAIL_BUILD
    val externalNames: ExternalNamesMode = ExternalNamesMode.PRESERVE_AND_REPORT

    const val reuseVariantSigningConfig = true
    val benchmarkMode: BenchmarkMode = BenchmarkMode.REPORT_ONLY
    val legacyPluginMode: LegacyPluginMode = LegacyPluginMode.PRESERVE_UNMANAGED
    const val verifyLegacyPluginCompatibility = true

    val similarityMode: SimilarityMode = SimilarityMode.OWNED_AAB_APK
    const val enforceRelativeImprovement = true
    const val enforceMaximumOverall = false
    const val enforceMaximumAabGrowth = false

    const val autoSelectSingleDevice = true
    const val applicationIdFromVariant = true
    const val launchActivityFromManifest = true
    const val deviceStabilitySeconds = 30
}
