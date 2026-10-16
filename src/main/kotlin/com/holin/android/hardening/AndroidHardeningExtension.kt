package com.holin.android.hardening

import com.holin.android.hardening.state.FixedSeedDerivation
import java.nio.file.Files
import java.util.Collections
import javax.inject.Inject
import org.gradle.api.Action
import org.gradle.api.Named
import org.gradle.api.NamedDomainObjectContainer
import org.gradle.api.Project
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.Directory
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.ProjectLayout
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.model.ObjectFactory
import org.gradle.api.provider.Property
import org.gradle.api.provider.Provider
import org.gradle.api.provider.SetProperty

open class AndroidHardeningExtension @Inject constructor(
    objects: ObjectFactory,
    layout: ProjectLayout,
) {
    @Deprecated("The plugin reads -PandroidHardening first; keep this property only for compatibility.")
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val projectKey: Property<String> = objects.property(String::class.java)
    val variants: VariantSelection = objects.newInstance(VariantSelection::class.java, objects)
    val ownership: OwnershipSpec = objects.newInstance(OwnershipSpec::class.java, objects)
    val rules: RulesSpec = objects.newInstance(RulesSpec::class.java, objects)
    val mapping: MappingSpec = objects.newInstance(MappingSpec::class.java, objects, layout)
    val reproducibility: ReproducibilitySpec = objects.newInstance(ReproducibilitySpec::class.java, objects)
    val naming: NamingSpec = objects.newInstance(NamingSpec::class.java, objects)
    val code: CodeSpec = objects.newInstance(CodeSpec::class.java, objects)
    val resources: ResourcesSpec = objects.newInstance(ResourcesSpec::class.java, objects)
    val dependencies: DependenciesSpec = objects.newInstance(DependenciesSpec::class.java, objects)
    val nativeLibraries: NativeLibrariesSpec = objects.newInstance(NativeLibrariesSpec::class.java, objects)
    val runtimeProtection: RuntimeProtectionSpec = objects.newInstance(RuntimeProtectionSpec::class.java, objects)
    val components: ComponentsSpec = objects.newInstance(ComponentsSpec::class.java, objects)
    val assets: AssetsSpec = objects.newInstance(AssetsSpec::class.java, objects)
    val verification: VerificationSpec = objects.newInstance(VerificationSpec::class.java, objects)
    val bundle: BundleSpec = objects.newInstance(BundleSpec::class.java, objects)
    val contracts: ContractsSpec = objects.newInstance(ContractsSpec::class.java, objects)
    val signing: SigningSpec = objects.newInstance(SigningSpec::class.java, objects)
    val benchmark: BenchmarkSpec = objects.newInstance(BenchmarkSpec::class.java, objects)
    val similarity: SimilaritySpec = objects.newInstance(SimilaritySpec::class.java, objects, layout)
    val deviceAcceptance: DeviceAcceptanceSpec = objects.newInstance(DeviceAcceptanceSpec::class.java, objects)
    val legacyPlugins: LegacyPluginsSpec = objects.newInstance(LegacyPluginsSpec::class.java, objects)
    val compatibility: CompatibilitySpec = objects.newInstance(CompatibilitySpec::class.java, objects)

    internal var effectiveEnabled: Provider<Boolean> = enabled
        private set
    internal var effectiveFixedSeed: Provider<String> = reproducibility.fixedSeed
        private set

    internal fun bindProjectProperties(project: Project) {
        val enabledProperty = project.gradle.startParameter.projectProperties["androidHardening"]
        effectiveEnabled = if (enabledProperty == null) {
            enabled
        } else {
            project.provider { enabledProperty.toBoolean() }
        }
        val fixedSeedProperty = project.gradle.startParameter.projectProperties["androidHardeningFixedSeed"]
        effectiveFixedSeed = if (fixedSeedProperty == null) {
            reproducibility.fixedSeed
        } else {
            project.provider { fixedSeedProperty }
        }
    }

    @Deprecated("Use targetVariants(\"variantName\") instead.")
    fun variants(action: Action<in VariantSelection>) = action.execute(variants)
    fun ownership(action: Action<in OwnershipSpec>) = action.execute(ownership)
    @Deprecated("Use proguardRules { ... } instead.")
    fun rules(action: Action<in RulesSpec>) = action.execute(rules)
    fun mapping(action: Action<in MappingSpec>) = action.execute(mapping)
    @Deprecated("The fixed seed is read from -PandroidHardeningFixedSeed first.")
    fun reproducibility(action: Action<in ReproducibilitySpec>) = action.execute(reproducibility)
    @Deprecated("The v1 naming policy is fixed by the plugin.")
    fun naming(action: Action<in NamingSpec>) = action.execute(naming)
    fun code(action: Action<in CodeSpec>) = action.execute(code)
    fun resources(action: Action<in ResourcesSpec>) = action.execute(resources)
    @Deprecated("Use dependencyProtection { ... } instead.")
    fun dependencies(action: Action<in DependenciesSpec>) = action.execute(dependencies)
    @Deprecated("Use nativeProtection { ... } instead.")
    fun nativeLibraries(action: Action<in NativeLibrariesSpec>) = action.execute(nativeLibraries)
    fun runtimeProtection(action: Action<in RuntimeProtectionSpec>) = action.execute(runtimeProtection)
    @Deprecated("Use componentProtection { ... } instead.")
    fun components(action: Action<in ComponentsSpec>) = action.execute(components)
    @Deprecated("Use assetProtection { ... } instead.")
    fun assets(action: Action<in AssetsSpec>) = action.execute(assets)
    fun verification(action: Action<in VerificationSpec>) = action.execute(verification)
    @Deprecated("Use bundleMetadata { ... } instead.")
    fun bundle(action: Action<in BundleSpec>) = action.execute(bundle)
    @Deprecated("The v1 contract policy is fixed by the plugin.")
    fun contracts(action: Action<in ContractsSpec>) = action.execute(contracts)
    @Deprecated("The v1 signing policy is fixed by the plugin.")
    fun signing(action: Action<in SigningSpec>) = action.execute(signing)
    @Deprecated("The v1 benchmark policy is fixed by the plugin.")
    fun benchmark(action: Action<in BenchmarkSpec>) = action.execute(benchmark)
    @Deprecated("Use similarityCheck { ... } instead.")
    fun similarity(action: Action<in SimilaritySpec>) = action.execute(similarity)
    @Deprecated("Use deviceTest { ... } instead.")
    fun deviceAcceptance(action: Action<in DeviceAcceptanceSpec>) = action.execute(deviceAcceptance)
    @Deprecated("Use existingPlugins { ... } instead.")
    fun legacyPlugins(action: Action<in LegacyPluginsSpec>) = action.execute(legacyPlugins)
    fun compatibility(action: Action<in CompatibilitySpec>) = action.execute(compatibility)

    fun targetVariants(vararg names: String) {
        names.forEach(variants::include)
    }

    /** Adds existing ProGuard files; use the block overload for exact preservation or additional rules. */
    fun proguardRules(vararg files: Any) {
        rules.sourceFiles.from(*files)
    }

    fun proguardRules(action: Action<in RulesSpec>) = action.execute(rules)
    fun existingPlugins(action: Action<in LegacyPluginsSpec>) = action.execute(legacyPlugins)
    fun bundleMetadata(action: Action<in BundleSpec>) = action.execute(bundle)
    fun similarityCheck(action: Action<in SimilaritySpec>) = action.execute(similarity)
    fun deviceTest(action: Action<in DeviceAcceptanceSpec>) = action.execute(deviceAcceptance)
    fun dependencyProtection(action: Action<in DependenciesSpec>) = action.execute(dependencies)
    fun nativeProtection(action: Action<in NativeLibrariesSpec>) = action.execute(nativeLibraries)
    fun assetProtection(action: Action<in AssetsSpec>) = action.execute(assets)
    fun componentProtection(action: Action<in ComponentsSpec>) = action.execute(components)
    val REPORT_ONLY: BenchmarkMode get() = BenchmarkMode.REPORT_ONLY

    fun validateV1(): ValidatedHardeningConfiguration {
        dependencies.policy()
        nativeLibraries.policy()
        runtimeProtection.policy()
        components.policy()
        assets.policy()
        resources.values.policy()
        val validatedProjectKey = HardeningNames.requireProjectKey(projectKey.get())
        val validatedVariants = variants.included.get().map(HardeningNames::requireVariant).toSet()
        require(validatedVariants.isNotEmpty()) { "variants must include at least one variant" }
        effectiveFixedSeed.orNull?.let(FixedSeedDerivation::seedSha256)
        require(mapping.lockTimeoutSeconds.get() > 0) { "mapping.lockTimeoutSeconds must be greater than zero" }
        requireFraction("code.diversification.minimumCoverage", code.diversification.minimumCoverage.get())
        require(code.diversification.minimumSimHashDistance.get() in 0..64) {
            "code.diversification.minimumSimHashDistance must be in 0..64"
        }
        requireFraction("code.diversification.maximumGrowth", code.diversification.maximumGrowth.get())
        requireFraction("resources.bitmapDiversification.minimumCoverage", resources.bitmapDiversification.minimumCoverage.get())
        if (resources.bitmapDiversification.mode.get() == com.holin.android.hardening.resources.BitmapMode.PIXEL_EXACT) {
            require(resources.bitmapDiversification.minimumPHashDistance.get() == 0 && resources.bitmapDiversification.minimumSsim.get() == 1.0) {
                "PIXEL_EXACT requires minimumPHashDistance=0 and minimumSsim=1.0"
            }
        } else {
            require(resources.bitmapDiversification.minimumPHashDistance.get() in 11..64)
        }
        requireFraction("resources.bitmapDiversification.minimumSsim", resources.bitmapDiversification.minimumSsim.get())
        require(bundle.structuralMetadataEntryCount.get() in 0..64) {
            "bundle.structuralMetadataEntryCount must be in 0..64"
        }
        require(similarity.maximumOverallExclusive.get() in 0.0..100.0) {
            "similarity.maximumOverallExclusive must be in 0.0..100.0"
        }
        requireFraction("similarity.maximumAabGrowth", similarity.maximumAabGrowth.get())
        require(similarity.mode.get() == HardeningV1Policy.similarityMode) {
            "similarity.mode only supports OWNED_AAB_APK in v1"
        }
        require(similarity.minimumImprovementPoints.get() in 0.01..100.0) {
            "similarity.minimumImprovementPoints must be in 0.01..100.0"
        }
        require(similarity.enforceRelativeImprovement.get() == HardeningV1Policy.enforceRelativeImprovement) {
            "similarity.enforceRelativeImprovement only supports true in v1"
        }
        require(similarity.enforceMaximumOverall.get() == HardeningV1Policy.enforceMaximumOverall) {
            "similarity.enforceMaximumOverall only supports false in v1"
        }
        require(similarity.enforceMaximumAabGrowth.get() == HardeningV1Policy.enforceMaximumAabGrowth) {
            "similarity.enforceMaximumAabGrowth only supports false in v1"
        }
        deviceAcceptance.serial.orNull?.let { serial ->
            require(serial.isNotBlank() && serial.none(Char::isWhitespace)) {
                "deviceAcceptance.serial must be a single nonblank token"
            }
        }
        deviceAcceptance.applicationId.orNull?.let { applicationId ->
            require(applicationId.isNotBlank()) { "deviceAcceptance.applicationId override must be nonblank" }
        }
        require(deviceAcceptance.applicationId.isPresent || deviceAcceptance.applicationIdFromVariant.get()) {
            "deviceAcceptance requires applicationId or applicationIdFromVariant=true"
        }
        deviceAcceptance.launchActivity.orNull?.let { launchActivity ->
            require(launchActivity.isNotBlank()) { "deviceAcceptance.launchActivity override must be nonblank" }
        }
        require(deviceAcceptance.launchActivity.isPresent || deviceAcceptance.launchActivityFromManifest.get()) {
            "deviceAcceptance requires launchActivity or launchActivityFromManifest=true"
        }
        // Legacy disabled fallbacks are equivalent when their explicit override is supplied.
        // Never turn an old request for manual device selection into an automatic installation.
        require(deviceAcceptance.serial.isPresent || deviceAcceptance.autoSelectSingleDevice.get()) {
            "deviceAcceptance requires serial when autoSelectSingleDevice=false; use deviceTest { serial.set(...) }"
        }
        require(deviceAcceptance.stabilitySeconds.get() == HardeningV1Policy.deviceStabilitySeconds) {
            "deviceAcceptance.stabilitySeconds must be 30 in v1"
        }
        require(naming.strategy.get() == HardeningV1Policy.namingStrategy) { "naming.strategy only supports TYPED_PSEUDOWORDS in v1" }
        require(mapping.reusePrevious.get() == HardeningV1Policy.mappingReusePrevious) { "mapping.reusePrevious only supports true in v1" }
        require(mapping.missingPolicy.get() == HardeningV1Policy.mappingMissingPolicy) { "mapping.missingPolicy only supports RECREATE in v1" }
        require(mapping.keepHistory.get() == HardeningV1Policy.mappingKeepHistory) { "mapping.keepHistory only supports true in v1" }
        require(mapping.quarantineInvalid.get() == HardeningV1Policy.mappingQuarantineInvalid) { "mapping.quarantineInvalid only supports true in v1" }
        require(naming.renamePackages.get() == HardeningV1Policy.namingRenamePackages) { "naming.renamePackages only supports true in v1" }
        require(naming.reuseAcrossBuilds.get() == HardeningV1Policy.namingReuseAcrossBuilds) { "naming.reuseAcrossBuilds only supports true in v1" }
        require(code.engine.get() == HardeningV1Policy.codeEngine) { "code.engine only supports R8 in v1" }
        require(code.preserveLineNumbers.get() == HardeningV1Policy.codePreserveLineNumbers) { "code.preserveLineNumbers only supports true in v1" }
        require(code.sourceFileMode.get() == HardeningV1Policy.codeSourceFileMode) { "code.sourceFileMode only supports PSEUDONYMIZE in v1" }
        require(code.stringFog.get() == HardeningV1Policy.codeStringFog) { "code.stringFog only supports PRESERVE_CURRENT in v1" }
        require(code.diversification.mode.get() == HardeningV1Policy.codeDiversificationMode) { "code.diversification.mode only supports DEX in v1" }
        require(code.diversification.contentSalt.get() == HardeningV1Policy.codeContentSalt) {
            "code.diversification.contentSalt only supports FRESH_PER_BUILD in v1"
        }
        require(resources.mode.get() == HardeningV1Policy.resourceMode) { "resources.mode only supports RENAME_AND_AUDIT in v1" }
        require(resources.renameLayouts.get() == HardeningV1Policy.resourceRenameLayouts) { "resources.renameLayouts only supports true in v1" }
        require(resources.renameDrawables.get() == HardeningV1Policy.resourceRenameDrawables) { "resources.renameDrawables only supports true in v1" }
        require(resources.renameStyles.get() == HardeningV1Policy.resourceRenameStyles) { "resources.renameStyles only supports true in v1" }
        require(resources.preserveResourceIds.get() == HardeningV1Policy.resourcePreserveIds) { "resources.preserveResourceIds only supports true in v1" }
        require(resources.reuseNamesAcrossBuilds.get() == HardeningV1Policy.resourceReuseNamesAcrossBuilds) { "resources.reuseNamesAcrossBuilds only supports true in v1" }
        require(resources.styleHashPolicy.get() == HardeningV1Policy.resourceStyleHashPolicy) { "resources.styleHashPolicy only supports RESOURCE_TABLE_ONLY in v1" }
        require(resources.bitmapDiversification.safeOnly.get() == HardeningV1Policy.bitmapSafeOnly) { "resources.bitmapDiversification.safeOnly only supports true in v1" }
        require(contracts.unresolvedAppReflection.get() == HardeningV1Policy.unresolvedAppReflection) { "contracts.unresolvedAppReflection only supports FAIL_BUILD in v1" }
        require(contracts.unresolvedResourceLookup.get() == HardeningV1Policy.unresolvedResourceLookup) { "contracts.unresolvedResourceLookup only supports FAIL_BUILD in v1" }
        require(contracts.externalNames.get() == HardeningV1Policy.externalNames) { "contracts.externalNames only supports PRESERVE_AND_REPORT in v1" }
        require(signing.reuseVariantSigningConfig.get() == HardeningV1Policy.reuseVariantSigningConfig) { "signing.reuseVariantSigningConfig only supports true in v1" }
        require(benchmark.mode.get() == HardeningV1Policy.benchmarkMode) { "benchmark.mode only supports REPORT_ONLY in v1" }
        require(legacyPlugins.mode.get() == HardeningV1Policy.legacyPluginMode) { "legacyPlugins.mode only supports PRESERVE_UNMANAGED in v1" }
        require(legacyPlugins.verifyCompatibility.get() == HardeningV1Policy.verifyLegacyPluginCompatibility) { "legacyPlugins.verifyCompatibility only supports true in v1" }
        require(ownership.modules.get().isNotEmpty()) {
            "androidHardening.ownership must declare at least one module"
        }
        return ValidatedHardeningConfiguration(
            effectiveEnabled.get(),
            validatedProjectKey,
            validatedVariants,
            mapping.storeDirectory.get(),
            mapping.lockTimeoutSeconds.get(),
        )
    }

    private fun requireFraction(label: String, value: Double) {
        require(value in 0.0..1.0) { "$label must be in 0.0..1.0" }
    }
}

data class ValidatedHardeningConfiguration(
    val enabled: Boolean,
    val projectKey: String,
    val variants: Set<String>,
    val storeDirectory: Directory,
    val lockTimeoutSeconds: Int,
)

open class VariantSelection @Inject constructor(objects: ObjectFactory) {
    val included: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())

    fun include(name: String) {
        included.add(HardeningNames.requireVariant(name))
    }
}

open class MappingSpec @Inject constructor(objects: ObjectFactory, layout: ProjectLayout) {
    val storeDirectory: DirectoryProperty = objects.directoryProperty().convention(layout.projectDirectory.dir(".hardening/mappings"))
    @Deprecated("The v1 mapping policy is fixed by the plugin.")
    val reusePrevious: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("The v1 mapping policy is fixed by the plugin.")
    val missingPolicy: Property<MissingPolicy> = objects.property(MissingPolicy::class.java).convention(MissingPolicy.RECREATE)
    @Deprecated("The v1 mapping policy is fixed by the plugin.")
    val keepHistory: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("The v1 mapping policy is fixed by the plugin.")
    val quarantineInvalid: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val lockTimeoutSeconds: Property<Int> = objects.property(Int::class.java).convention(60)
    val RECREATE: MissingPolicy get() = MissingPolicy.RECREATE
}

open class ReproducibilitySpec @Inject constructor(objects: ObjectFactory) {
    @Deprecated("Use -PandroidHardeningFixedSeed; this property is a compatibility fallback.")
    val fixedSeed: Property<String> = objects.property(String::class.java)
}

open class NamingSpec @Inject constructor(objects: ObjectFactory) {
    @Deprecated("The v1 naming policy is fixed by the plugin.")
    val strategy: Property<NamingStrategy> = objects.property(NamingStrategy::class.java).convention(NamingStrategy.TYPED_PSEUDOWORDS)
    @Deprecated("The v1 naming policy is fixed by the plugin.")
    val renamePackages: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("The v1 naming policy is fixed by the plugin.")
    val reuseAcrossBuilds: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val TYPED_PSEUDOWORDS: NamingStrategy get() = NamingStrategy.TYPED_PSEUDOWORDS
}

open class CodeSpec @Inject constructor(objects: ObjectFactory) {
    @Deprecated("The v1 code policy is fixed by the plugin.")
    val engine: Property<CodeEngine> = objects.property(CodeEngine::class.java).convention(CodeEngine.R8)
    @Deprecated("The v1 code policy is fixed by the plugin.")
    val preserveLineNumbers: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("The v1 code policy is fixed by the plugin.")
    val sourceFileMode: Property<SourceFileMode> = objects.property(SourceFileMode::class.java).convention(SourceFileMode.PSEUDONYMIZE)
    @Deprecated("The v1 code policy is fixed by the plugin.")
    val stringFog: Property<StringFogMode> = objects.property(StringFogMode::class.java).convention(StringFogMode.PRESERVE_CURRENT)
    val diversification: DiversificationSpec = objects.newInstance(DiversificationSpec::class.java, objects)

    fun diversification(action: Action<in DiversificationSpec>) = action.execute(diversification)
    val R8: CodeEngine get() = CodeEngine.R8
    val PSEUDONYMIZE: SourceFileMode get() = SourceFileMode.PSEUDONYMIZE
    val PRESERVE_CURRENT: StringFogMode get() = StringFogMode.PRESERVE_CURRENT
}

open class DiversificationSpec @Inject constructor(objects: ObjectFactory) {
    @Deprecated("The v1 code policy is fixed by the plugin.")
    val mode: Property<DiversificationMode> = objects.property(DiversificationMode::class.java).convention(DiversificationMode.DEX)
    @Deprecated("The v1 code policy is fixed by the plugin.")
    val contentSalt: Property<ContentSaltMode> = objects.property(ContentSaltMode::class.java).convention(ContentSaltMode.FRESH_PER_BUILD)
    val minimumCoverage: Property<Double> = objects.property(Double::class.java).convention(0.50)
    val minimumSimHashDistance: Property<Int> = objects.property(Int::class.java).convention(4)
    val maximumGrowth: Property<Double> = objects.property(Double::class.java).convention(0.05)
    val enforceMaximumGrowth: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val DEX: DiversificationMode get() = DiversificationMode.DEX
    val FRESH_PER_BUILD: ContentSaltMode get() = ContentSaltMode.FRESH_PER_BUILD
}

open class ResourcesSpec @Inject constructor(objects: ObjectFactory) {
    @Deprecated("The v1 resource naming policy is fixed by the plugin.")
    val mode: Property<ResourceMode> = objects.property(ResourceMode::class.java).convention(ResourceMode.RENAME_AND_AUDIT)
    @Deprecated("The v1 resource naming policy is fixed by the plugin.")
    val renameLayouts: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("The v1 resource naming policy is fixed by the plugin.")
    val renameDrawables: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("The v1 resource naming policy is fixed by the plugin.")
    val renameStyles: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("The v1 resource naming policy is fixed by the plugin.")
    val preserveResourceIds: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("The v1 resource naming policy is fixed by the plugin.")
    val reuseNamesAcrossBuilds: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("The v1 resource naming policy is fixed by the plugin.")
    val styleHashPolicy: Property<StyleHashPolicy> = objects.property(StyleHashPolicy::class.java).convention(StyleHashPolicy.RESOURCE_TABLE_ONLY)
    val values: ValueResourcesSpec = objects.newInstance(ValueResourcesSpec::class.java, objects)
    val bitmapDiversification: BitmapDiversificationSpec = objects.newInstance(BitmapDiversificationSpec::class.java, objects)

    fun values(action: Action<in ValueResourcesSpec>) = action.execute(values)
    fun bitmapDiversification(action: Action<in BitmapDiversificationSpec>) = action.execute(bitmapDiversification)
    val RENAME_AND_AUDIT: ResourceMode get() = ResourceMode.RENAME_AND_AUDIT
    val RESOURCE_TABLE_ONLY: StyleHashPolicy get() = StyleHashPolicy.RESOURCE_TABLE_ONLY
}

open class BitmapDiversificationSpec @Inject constructor(objects: ObjectFactory) {
    val mode: Property<com.holin.android.hardening.resources.BitmapMode> = objects.property(com.holin.android.hardening.resources.BitmapMode::class.java).convention(com.holin.android.hardening.resources.BitmapMode.LEGACY_PERCEPTUAL)
    val PIXEL_EXACT: com.holin.android.hardening.resources.BitmapMode get() = com.holin.android.hardening.resources.BitmapMode.PIXEL_EXACT
    val LEGACY_PERCEPTUAL: com.holin.android.hardening.resources.BitmapMode get() = com.holin.android.hardening.resources.BitmapMode.LEGACY_PERCEPTUAL
    @Deprecated("The v1 image safety policy is fixed by the plugin.")
    val safeOnly: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val minimumCoverage: Property<Double> = objects.property(Double::class.java).convention(0.90)
    val minimumPHashDistance: Property<Int> = objects.property(Int::class.java).convention(11)
    val minimumSsim: Property<Double> = objects.property(Double::class.java).convention(0.995)
}

open class BundleSpec @Inject constructor(objects: ObjectFactory) {
    val dependencyMetadata: Property<DependencyMetadataMode> =
        objects.property(DependencyMetadataMode::class.java).convention(DependencyMetadataMode.PRESERVE)
    val structuralMetadataEntryCount: Property<Int> = objects.property(Int::class.java).convention(0)

    val PRESERVE: DependencyMetadataMode get() = DependencyMetadataMode.PRESERVE
    val OMIT: DependencyMetadataMode get() = DependencyMetadataMode.OMIT
}

open class ContractsSpec @Inject constructor(objects: ObjectFactory) {
    @Deprecated("The v1 contract policy is fixed by the plugin.")
    val unresolvedAppReflection: Property<UnresolvedContractPolicy> = objects.property(UnresolvedContractPolicy::class.java).convention(UnresolvedContractPolicy.FAIL_BUILD)
    @Deprecated("The v1 contract policy is fixed by the plugin.")
    val unresolvedResourceLookup: Property<UnresolvedContractPolicy> = objects.property(UnresolvedContractPolicy::class.java).convention(UnresolvedContractPolicy.FAIL_BUILD)
    @Deprecated("The v1 contract policy is fixed by the plugin.")
    val externalNames: Property<ExternalNamesMode> = objects.property(ExternalNamesMode::class.java).convention(ExternalNamesMode.PRESERVE_AND_REPORT)
    val FAIL_BUILD: UnresolvedContractPolicy get() = UnresolvedContractPolicy.FAIL_BUILD
    val PRESERVE_AND_REPORT: ExternalNamesMode get() = ExternalNamesMode.PRESERVE_AND_REPORT
}

open class SigningSpec @Inject constructor(objects: ObjectFactory) {
    @Deprecated("The v1 signing policy is fixed by the plugin.")
    val reuseVariantSigningConfig: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
}

open class BenchmarkSpec @Inject constructor(objects: ObjectFactory) {
    @Deprecated("The v1 benchmark policy is fixed by the plugin.")
    val mode: Property<BenchmarkMode> = objects.property(BenchmarkMode::class.java).convention(BenchmarkMode.REPORT_ONLY)
    val REPORT_ONLY: BenchmarkMode get() = BenchmarkMode.REPORT_ONLY
}

open class SimilaritySpec @Inject constructor(objects: ObjectFactory, layout: ProjectLayout) {
    @Deprecated("The v1 comparison mode is fixed by the plugin.")
    val mode: Property<SimilarityMode> = objects.property(SimilarityMode::class.java).convention(SimilarityMode.OWNED_AAB_APK)
    val baselineDirectory: DirectoryProperty = objects.directoryProperty()
        .convention(layout.projectDirectory.dir(".hardening/baselines"))
    val minimumImprovementPoints: Property<Double> = objects.property(Double::class.java).convention(0.01)
    @Deprecated("The v1 relative comparison gate is always enabled.")
    val enforceRelativeImprovement: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("Compatibility value only; absolute score gating is not active in v1.")
    /** A score equal to this value is rejected. */
    val maximumOverallExclusive: Property<Double> = objects.property(Double::class.java).convention(75.0)
    @Deprecated("Compatibility value only; absolute score gating is not active in v1.")
    val enforceMaximumOverall: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    @Deprecated("Compatibility value only; AAB growth gating is not active in v1.")
    val maximumAabGrowth: Property<Double> = objects.property(Double::class.java).convention(0.10)
    @Deprecated("Compatibility value only; AAB growth gating is not active in v1.")
    val enforceMaximumAabGrowth: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val OWNED_AAB_APK: SimilarityMode get() = SimilarityMode.OWNED_AAB_APK
}

open class DeviceAcceptanceSpec @Inject constructor(objects: ObjectFactory) {
    val serial: Property<String> = objects.property(String::class.java)
    @Deprecated("A unique online device is selected automatically in v1.")
    val autoSelectSingleDevice: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val applicationId: Property<String> = objects.property(String::class.java)
    @Deprecated("Variant applicationId fallback is built into v1.")
    val applicationIdFromVariant: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val launchActivity: Property<String> = objects.property(String::class.java)
    @Deprecated("Manifest launcher fallback is built into v1.")
    val launchActivityFromManifest: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    @Deprecated("The v1 device observation window is fixed at 30 seconds.")
    val stabilitySeconds: Property<Int> = objects.property(Int::class.java).convention(30)
}

open class RulesSpec @Inject constructor(objects: ObjectFactory) {
    val sourceFiles: ConfigurableFileCollection = objects.fileCollection()
    val preserveExactRules: ConfigurableFileCollection = objects.fileCollection()
    val additionalRules: ConfigurableFileCollection = objects.fileCollection()
}

open class LegacyPluginsSpec @Inject constructor(objects: ObjectFactory) {
    @Deprecated("The v1 legacy plugin mode is fixed by the plugin.")
    val mode: Property<LegacyPluginMode> = objects.property(LegacyPluginMode::class.java).convention(LegacyPluginMode.PRESERVE_UNMANAGED)
    @Deprecated("Compatibility verification is always enabled in v1.")
    val verifyCompatibility: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val baselineFile: RegularFileProperty = objects.fileProperty()
    val plugins: NamedDomainObjectContainer<LegacyPluginSpec> = objects.domainObjectContainer(
        LegacyPluginSpec::class.java,
    ) { name -> objects.newInstance(LegacyPluginSpec::class.java, name, objects) }
    val PRESERVE_UNMANAGED: LegacyPluginMode get() = LegacyPluginMode.PRESERVE_UNMANAGED

    fun plugin(name: String, action: Action<in LegacyPluginSpec>) {
        action.execute(plugins.maybeCreate(name))
    }

    internal fun resolve(rootProject: Project): List<LegacyPluginDeclaration> {
        val root = rootProject.projectDir.toPath().toAbsolutePath().normalize()
        val resolved = plugins.map { plugin ->
            val pluginId = plugin.pluginId.orNull?.trim().orEmpty()
            val expectedVersion = plugin.expectedVersion.orNull?.trim().orEmpty()
            require(PLUGIN_ID.matches(pluginId)) { "legacy plugin ${plugin.name} pluginId is missing or malformed" }
            require(expectedVersion.isNotEmpty()) { "legacy plugin ${plugin.name} expectedVersion is missing" }
            LegacyPluginDeclaration(
                plugin.name,
                pluginId,
                expectedVersion,
                immutablePaths(
                    root,
                    plugin.configurationInputs.files.map { it.toPath() },
                    "legacy plugin ${plugin.name} configuration input",
                    true,
                ),
                immutablePaths(
                    root,
                    plugin.mappingPaths.files.map { it.toPath() },
                    "legacy plugin ${plugin.name} mapping path",
                    false,
                ),
            )
        }.sortedBy(LegacyPluginDeclaration::name)
        require(resolved.map(LegacyPluginDeclaration::pluginId).distinct().size == resolved.size) {
            "legacy plugin declarations contain duplicate pluginId values"
        }
        return Collections.unmodifiableList(resolved)
    }

    private fun immutablePaths(
        root: java.nio.file.Path,
        paths: List<java.nio.file.Path>,
        label: String,
        requireExisting: Boolean,
    ): List<String> = Collections.unmodifiableList(
        paths.map { path ->
            val normalized = path.toAbsolutePath().normalize()
            require(normalized.startsWith(root) && normalized != root) { "$label escapes the repository boundary" }
            require(!Files.isSymbolicLink(normalized)) { "$label must not be a symbolic link: $normalized" }
            if (requireExisting) {
                require(Files.isRegularFile(normalized)) { "$label is missing or is not a regular file: $normalized" }
            }
            root.relativize(normalized).toString().replace(java.io.File.separatorChar, '/')
        }.distinct().sorted(),
    )

    private companion object {
        val PLUGIN_ID = Regex("[A-Za-z0-9_.-]+")
    }
}

open class LegacyPluginSpec @Inject constructor(
    private val declarationName: String,
    objects: ObjectFactory,
) : Named {
    override fun getName(): String = declarationName
    val pluginId: Property<String> = objects.property(String::class.java)
    val expectedVersion: Property<String> = objects.property(String::class.java)
    val configurationInputs: ConfigurableFileCollection = objects.fileCollection()
    val mappingPaths: ConfigurableFileCollection = objects.fileCollection()
}

data class LegacyPluginDeclaration(
    val name: String,
    val pluginId: String,
    val expectedVersion: String,
    val configurationInputs: List<String>,
    val mappingPaths: List<String>,
)

open class CompatibilitySpec @Inject constructor(objects: ObjectFactory) {
    val autoMigrateLegacyState: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val migrationDescriptor: RegularFileProperty = objects.fileProperty()
}

open class VerificationSpec @Inject constructor(objects: ObjectFactory) {
    val debuggableApkVariants: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
}

open class ValueResourcesSpec @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val includes: SetProperty<String> = objects.setProperty(String::class.java).convention(setOf("string/*", "color/*", "dimen/*"))
    val excludes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val minimumCoverage: Property<Double> = objects.property(Double::class.java).convention(0.0)
    fun policy(): com.holin.android.hardening.resources.ValueResourcePolicy =
        com.holin.android.hardening.resources.ValueResourcePolicy(enabled.get(), includes.get(), excludes.get(), minimumCoverage.get())
}

open class AssetsSpec @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val includes: SetProperty<String> = objects.setProperty(String::class.java).convention(setOf("**"))
    val excludes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val images: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val fonts: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val json: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val minimumCoverage: Property<Double> = objects.property(Double::class.java).convention(0.0)
    fun policy(): com.holin.android.hardening.resources.AssetPolicy =
        com.holin.android.hardening.resources.AssetPolicy(enabled.get(), includes.get(), excludes.get(), images.get(), fonts.get(), json.get(), minimumCoverage.get())
}

open class ComponentsSpec @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val includes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val excludes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val minimumCoverage: Property<Double> = objects.property(Double::class.java).convention(0.0)
    fun policy() = com.holin.android.hardening.components.ComponentPolicy(enabled.get(), includes.get(), excludes.get(), minimumCoverage.get())
}

open class RuntimeProtectionSpec @Inject constructor(objects: ObjectFactory) {
    val strings: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val minimumStringCoverage: Property<Double> = objects.property(Double::class.java).convention(0.0)
    val assetPaths: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val assetReaders: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val minimumAssetCoverage: Property<Double> = objects.property(Double::class.java).convention(0.0)
    val images: RuntimeImagesSpec = objects.newInstance(RuntimeImagesSpec::class.java)
    fun images(action: Action<in RuntimeImagesSpec>) = action.execute(images)
    fun policy() = com.holin.android.hardening.runtime.RuntimeProtectionPolicy(strings.get(), minimumStringCoverage.get(),
        assetPaths.get(), assetReaders.get(), minimumAssetCoverage.get(), images.policy())
}

open class RuntimeImagesSpec @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val includes: SetProperty<String> = objects.setProperty(String::class.java).convention(setOf("drawable/*"))
    val excludes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val minimumCoverage: Property<Double> = objects.property(Double::class.java).convention(0.0)
    fun policy() = com.holin.android.hardening.runtime.RuntimeImagePolicy(enabled.get(), includes.get(), excludes.get(), minimumCoverage.get())
}

open class NativeLibrariesSpec @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val includes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val excludes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val minimumCoverage: Property<Double> = objects.property(Double::class.java).convention(0.0)
    fun policy() = com.holin.android.hardening.nativecode.NativePolicy(enabled.get(), includes.get(), excludes.get(), minimumCoverage.get())
}

open class DependenciesSpec @Inject constructor(objects: ObjectFactory) {
    val enabled: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val includes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val excludes: SetProperty<String> = objects.setProperty(String::class.java).convention(emptySet())
    val minimumCoverage: Property<Double> = objects.property(Double::class.java).convention(0.0)
    fun policy() = com.holin.android.hardening.dependencies.DependencyPolicy(enabled.get(), includes.get(), excludes.get(), minimumCoverage.get())
}
