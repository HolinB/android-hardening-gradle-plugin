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
import org.gradle.api.provider.SetProperty

open class AndroidHardeningExtension @Inject constructor(
    objects: ObjectFactory,
    layout: ProjectLayout,
) {
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
    val contracts: ContractsSpec = objects.newInstance(ContractsSpec::class.java, objects)
    val signing: SigningSpec = objects.newInstance(SigningSpec::class.java, objects)
    val benchmark: BenchmarkSpec = objects.newInstance(BenchmarkSpec::class.java, objects)
    val similarity: SimilaritySpec = objects.newInstance(SimilaritySpec::class.java, objects, layout)
    val deviceAcceptance: DeviceAcceptanceSpec = objects.newInstance(DeviceAcceptanceSpec::class.java, objects)
    val legacyPlugins: LegacyPluginsSpec = objects.newInstance(LegacyPluginsSpec::class.java, objects)
    val compatibility: CompatibilitySpec = objects.newInstance(CompatibilitySpec::class.java, objects)

    fun variants(action: Action<in VariantSelection>) = action.execute(variants)
    fun ownership(action: Action<in OwnershipSpec>) = action.execute(ownership)
    fun rules(action: Action<in RulesSpec>) = action.execute(rules)
    fun mapping(action: Action<in MappingSpec>) = action.execute(mapping)
    fun reproducibility(action: Action<in ReproducibilitySpec>) = action.execute(reproducibility)
    fun naming(action: Action<in NamingSpec>) = action.execute(naming)
    fun code(action: Action<in CodeSpec>) = action.execute(code)
    fun resources(action: Action<in ResourcesSpec>) = action.execute(resources)
    fun contracts(action: Action<in ContractsSpec>) = action.execute(contracts)
    fun signing(action: Action<in SigningSpec>) = action.execute(signing)
    fun benchmark(action: Action<in BenchmarkSpec>) = action.execute(benchmark)
    fun similarity(action: Action<in SimilaritySpec>) = action.execute(similarity)
    fun deviceAcceptance(action: Action<in DeviceAcceptanceSpec>) = action.execute(deviceAcceptance)
    fun legacyPlugins(action: Action<in LegacyPluginsSpec>) = action.execute(legacyPlugins)
    fun compatibility(action: Action<in CompatibilitySpec>) = action.execute(compatibility)
    val REPORT_ONLY: BenchmarkMode get() = BenchmarkMode.REPORT_ONLY

    fun validateV1(): ValidatedHardeningConfiguration {
        val validatedProjectKey = HardeningNames.requireProjectKey(projectKey.get())
        val validatedVariants = variants.included.get().map(HardeningNames::requireVariant).toSet()
        require(validatedVariants.isNotEmpty()) { "variants must include at least one variant" }
        reproducibility.fixedSeed.orNull?.let(FixedSeedDerivation::seedSha256)
        require(mapping.lockTimeoutSeconds.get() > 0) { "mapping.lockTimeoutSeconds must be greater than zero" }
        requireFraction("code.diversification.minimumCoverage", code.diversification.minimumCoverage.get())
        require(code.diversification.minimumSimHashDistance.get() in 0..64) {
            "code.diversification.minimumSimHashDistance must be in 0..64"
        }
        requireFraction("code.diversification.maximumGrowth", code.diversification.maximumGrowth.get())
        requireFraction("resources.bitmapDiversification.minimumCoverage", resources.bitmapDiversification.minimumCoverage.get())
        require(resources.bitmapDiversification.minimumPHashDistance.get() in 11..64) {
            "resources.bitmapDiversification.minimumPHashDistance must be in 11..64"
        }
        requireFraction("resources.bitmapDiversification.minimumSsim", resources.bitmapDiversification.minimumSsim.get())
        require(similarity.maximumOverallExclusive.get() in 0.0..100.0) {
            "similarity.maximumOverallExclusive must be in 0.0..100.0"
        }
        requireFraction("similarity.maximumAabGrowth", similarity.maximumAabGrowth.get())
        require(similarity.mode.get() == SimilarityMode.OWNED_AAB_APK) {
            "similarity.mode only supports OWNED_AAB_APK in v1"
        }
        require(similarity.minimumImprovementPoints.get() in 0.01..100.0) {
            "similarity.minimumImprovementPoints must be in 0.01..100.0"
        }
        require(similarity.enforceRelativeImprovement.get()) {
            "similarity.enforceRelativeImprovement only supports true in v1"
        }
        require(!similarity.enforceMaximumOverall.get()) {
            "similarity.enforceMaximumOverall only supports false in v1"
        }
        require(!similarity.enforceMaximumAabGrowth.get()) {
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
        require(deviceAcceptance.stabilitySeconds.get() == 30) {
            "deviceAcceptance.stabilitySeconds must be 30 in v1"
        }
        require(naming.strategy.get() == NamingStrategy.TYPED_PSEUDOWORDS) { "naming.strategy only supports TYPED_PSEUDOWORDS in v1" }
        require(mapping.reusePrevious.get()) { "mapping.reusePrevious only supports true in v1" }
        require(mapping.missingPolicy.get() == MissingPolicy.RECREATE) { "mapping.missingPolicy only supports RECREATE in v1" }
        require(mapping.keepHistory.get()) { "mapping.keepHistory only supports true in v1" }
        require(mapping.quarantineInvalid.get()) { "mapping.quarantineInvalid only supports true in v1" }
        require(naming.renamePackages.get()) { "naming.renamePackages only supports true in v1" }
        require(naming.reuseAcrossBuilds.get()) { "naming.reuseAcrossBuilds only supports true in v1" }
        require(code.engine.get() == CodeEngine.R8) { "code.engine only supports R8 in v1" }
        require(code.preserveLineNumbers.get()) { "code.preserveLineNumbers only supports true in v1" }
        require(code.sourceFileMode.get() == SourceFileMode.PSEUDONYMIZE) { "code.sourceFileMode only supports PSEUDONYMIZE in v1" }
        require(code.stringFog.get() == StringFogMode.PRESERVE_CURRENT) { "code.stringFog only supports PRESERVE_CURRENT in v1" }
        require(code.diversification.mode.get() == DiversificationMode.DEX) { "code.diversification.mode only supports DEX in v1" }
        require(code.diversification.contentSalt.get() == ContentSaltMode.FRESH_PER_BUILD) {
            "code.diversification.contentSalt only supports FRESH_PER_BUILD in v1"
        }
        require(resources.mode.get() == ResourceMode.RENAME_AND_AUDIT) { "resources.mode only supports RENAME_AND_AUDIT in v1" }
        require(resources.renameLayouts.get()) { "resources.renameLayouts only supports true in v1" }
        require(resources.renameDrawables.get()) { "resources.renameDrawables only supports true in v1" }
        require(resources.renameStyles.get()) { "resources.renameStyles only supports true in v1" }
        require(resources.preserveResourceIds.get()) { "resources.preserveResourceIds only supports true in v1" }
        require(resources.reuseNamesAcrossBuilds.get()) { "resources.reuseNamesAcrossBuilds only supports true in v1" }
        require(resources.styleHashPolicy.get() == StyleHashPolicy.RESOURCE_TABLE_ONLY) { "resources.styleHashPolicy only supports RESOURCE_TABLE_ONLY in v1" }
        require(resources.bitmapDiversification.safeOnly.get()) { "resources.bitmapDiversification.safeOnly only supports true in v1" }
        require(contracts.unresolvedAppReflection.get() == UnresolvedContractPolicy.FAIL_BUILD) { "contracts.unresolvedAppReflection only supports FAIL_BUILD in v1" }
        require(contracts.unresolvedResourceLookup.get() == UnresolvedContractPolicy.FAIL_BUILD) { "contracts.unresolvedResourceLookup only supports FAIL_BUILD in v1" }
        require(contracts.externalNames.get() == ExternalNamesMode.PRESERVE_AND_REPORT) { "contracts.externalNames only supports PRESERVE_AND_REPORT in v1" }
        require(signing.reuseVariantSigningConfig.get()) { "signing.reuseVariantSigningConfig only supports true in v1" }
        require(benchmark.mode.get() == BenchmarkMode.REPORT_ONLY) { "benchmark.mode only supports REPORT_ONLY in v1" }
        require(legacyPlugins.mode.get() == LegacyPluginMode.PRESERVE_UNMANAGED) { "legacyPlugins.mode only supports PRESERVE_UNMANAGED in v1" }
        require(legacyPlugins.verifyCompatibility.get()) { "legacyPlugins.verifyCompatibility only supports true in v1" }
        require(ownership.modules.get().isNotEmpty()) {
            "androidHardening.ownership must declare at least one module"
        }
        return ValidatedHardeningConfiguration(
            enabled = enabled.get(),
            projectKey = validatedProjectKey,
            variants = validatedVariants,
            storeDirectory = mapping.storeDirectory.get(),
            lockTimeoutSeconds = mapping.lockTimeoutSeconds.get(),
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
    val reusePrevious: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val missingPolicy: Property<MissingPolicy> = objects.property(MissingPolicy::class.java).convention(MissingPolicy.RECREATE)
    val keepHistory: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val quarantineInvalid: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val lockTimeoutSeconds: Property<Int> = objects.property(Int::class.java).convention(60)
    val RECREATE: MissingPolicy get() = MissingPolicy.RECREATE
}

open class ReproducibilitySpec @Inject constructor(objects: ObjectFactory) {
    val fixedSeed: Property<String> = objects.property(String::class.java)
}

open class NamingSpec @Inject constructor(objects: ObjectFactory) {
    val strategy: Property<NamingStrategy> = objects.property(NamingStrategy::class.java).convention(NamingStrategy.TYPED_PSEUDOWORDS)
    val renamePackages: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val reuseAcrossBuilds: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val TYPED_PSEUDOWORDS: NamingStrategy get() = NamingStrategy.TYPED_PSEUDOWORDS
}

open class CodeSpec @Inject constructor(objects: ObjectFactory) {
    val engine: Property<CodeEngine> = objects.property(CodeEngine::class.java).convention(CodeEngine.R8)
    val preserveLineNumbers: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val sourceFileMode: Property<SourceFileMode> = objects.property(SourceFileMode::class.java).convention(SourceFileMode.PSEUDONYMIZE)
    val stringFog: Property<StringFogMode> = objects.property(StringFogMode::class.java).convention(StringFogMode.PRESERVE_CURRENT)
    val diversification: DiversificationSpec = objects.newInstance(DiversificationSpec::class.java, objects)

    fun diversification(action: Action<in DiversificationSpec>) = action.execute(diversification)
    val R8: CodeEngine get() = CodeEngine.R8
    val PSEUDONYMIZE: SourceFileMode get() = SourceFileMode.PSEUDONYMIZE
    val PRESERVE_CURRENT: StringFogMode get() = StringFogMode.PRESERVE_CURRENT
}

open class DiversificationSpec @Inject constructor(objects: ObjectFactory) {
    val mode: Property<DiversificationMode> = objects.property(DiversificationMode::class.java).convention(DiversificationMode.DEX)
    val contentSalt: Property<ContentSaltMode> = objects.property(ContentSaltMode::class.java).convention(ContentSaltMode.FRESH_PER_BUILD)
    val minimumCoverage: Property<Double> = objects.property(Double::class.java).convention(0.50)
    val minimumSimHashDistance: Property<Int> = objects.property(Int::class.java).convention(4)
    val maximumGrowth: Property<Double> = objects.property(Double::class.java).convention(0.05)
    val enforceMaximumGrowth: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val DEX: DiversificationMode get() = DiversificationMode.DEX
    val FRESH_PER_BUILD: ContentSaltMode get() = ContentSaltMode.FRESH_PER_BUILD
}

open class ResourcesSpec @Inject constructor(objects: ObjectFactory) {
    val mode: Property<ResourceMode> = objects.property(ResourceMode::class.java).convention(ResourceMode.RENAME_AND_AUDIT)
    val renameLayouts: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val renameDrawables: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val renameStyles: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val preserveResourceIds: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val reuseNamesAcrossBuilds: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val styleHashPolicy: Property<StyleHashPolicy> = objects.property(StyleHashPolicy::class.java).convention(StyleHashPolicy.RESOURCE_TABLE_ONLY)
    val bitmapDiversification: BitmapDiversificationSpec = objects.newInstance(BitmapDiversificationSpec::class.java, objects)

    fun bitmapDiversification(action: Action<in BitmapDiversificationSpec>) = action.execute(bitmapDiversification)
    val RENAME_AND_AUDIT: ResourceMode get() = ResourceMode.RENAME_AND_AUDIT
    val RESOURCE_TABLE_ONLY: StyleHashPolicy get() = StyleHashPolicy.RESOURCE_TABLE_ONLY
}

open class BitmapDiversificationSpec @Inject constructor(objects: ObjectFactory) {
    val safeOnly: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val minimumCoverage: Property<Double> = objects.property(Double::class.java).convention(0.90)
    val minimumPHashDistance: Property<Int> = objects.property(Int::class.java).convention(11)
    val minimumSsim: Property<Double> = objects.property(Double::class.java).convention(0.995)
}

open class ContractsSpec @Inject constructor(objects: ObjectFactory) {
    val unresolvedAppReflection: Property<UnresolvedContractPolicy> = objects.property(UnresolvedContractPolicy::class.java).convention(UnresolvedContractPolicy.FAIL_BUILD)
    val unresolvedResourceLookup: Property<UnresolvedContractPolicy> = objects.property(UnresolvedContractPolicy::class.java).convention(UnresolvedContractPolicy.FAIL_BUILD)
    val externalNames: Property<ExternalNamesMode> = objects.property(ExternalNamesMode::class.java).convention(ExternalNamesMode.PRESERVE_AND_REPORT)
    val FAIL_BUILD: UnresolvedContractPolicy get() = UnresolvedContractPolicy.FAIL_BUILD
    val PRESERVE_AND_REPORT: ExternalNamesMode get() = ExternalNamesMode.PRESERVE_AND_REPORT
}

open class SigningSpec @Inject constructor(objects: ObjectFactory) {
    val reuseVariantSigningConfig: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
}

open class BenchmarkSpec @Inject constructor(objects: ObjectFactory) {
    val mode: Property<BenchmarkMode> = objects.property(BenchmarkMode::class.java).convention(BenchmarkMode.REPORT_ONLY)
    val REPORT_ONLY: BenchmarkMode get() = BenchmarkMode.REPORT_ONLY
}

open class SimilaritySpec @Inject constructor(objects: ObjectFactory, layout: ProjectLayout) {
    val mode: Property<SimilarityMode> = objects.property(SimilarityMode::class.java).convention(SimilarityMode.OWNED_AAB_APK)
    val baselineDirectory: DirectoryProperty = objects.directoryProperty()
        .convention(layout.projectDirectory.dir(".hardening/baselines"))
    val minimumImprovementPoints: Property<Double> = objects.property(Double::class.java).convention(0.01)
    val enforceRelativeImprovement: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    /** A score equal to this value is rejected. */
    val maximumOverallExclusive: Property<Double> = objects.property(Double::class.java).convention(75.0)
    val enforceMaximumOverall: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val maximumAabGrowth: Property<Double> = objects.property(Double::class.java).convention(0.10)
    val enforceMaximumAabGrowth: Property<Boolean> = objects.property(Boolean::class.java).convention(false)
    val OWNED_AAB_APK: SimilarityMode get() = SimilarityMode.OWNED_AAB_APK
}

open class DeviceAcceptanceSpec @Inject constructor(objects: ObjectFactory) {
    val serial: Property<String> = objects.property(String::class.java)
    val autoSelectSingleDevice: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val applicationId: Property<String> = objects.property(String::class.java)
    val applicationIdFromVariant: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val launchActivity: Property<String> = objects.property(String::class.java)
    val launchActivityFromManifest: Property<Boolean> = objects.property(Boolean::class.java).convention(true)
    val stabilitySeconds: Property<Int> = objects.property(Int::class.java).convention(30)
}

open class RulesSpec @Inject constructor(objects: ObjectFactory) {
    val sourceFiles: ConfigurableFileCollection = objects.fileCollection()
    val preserveExactRules: ConfigurableFileCollection = objects.fileCollection()
    val additionalRules: ConfigurableFileCollection = objects.fileCollection()
}

open class LegacyPluginsSpec @Inject constructor(objects: ObjectFactory) {
    val mode: Property<LegacyPluginMode> = objects.property(LegacyPluginMode::class.java).convention(LegacyPluginMode.PRESERVE_UNMANAGED)
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
