package com.holin.android.hardening.tasks

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.artifact.BundleVerificationReportCodec
import com.holin.android.hardening.artifact.ArtifactPathBoundary
import com.holin.android.hardening.artifact.HardenedBundlePlanReport
import com.holin.android.hardening.artifact.HardenedBundlePlanReportCodec
import com.holin.android.hardening.artifact.VerifiedArtifactPublisher
import com.holin.android.hardening.audit.HardeningAuditReport
import com.holin.android.hardening.audit.HardeningAuditReportCodec
import com.holin.android.hardening.audit.HardeningAuditStatus
import com.holin.android.hardening.audit.HardeningSourceAuditScanner
import com.holin.android.hardening.audit.HardcodedReferenceScopeReport
import com.holin.android.hardening.audit.HardeningSourceAudit
import com.holin.android.hardening.audit.LegacyCompatibilityStatus
import com.holin.android.hardening.audit.LegacyCompatibilityVerifier
import com.holin.android.hardening.audit.LegacyPluginBaselineVerifier
import com.holin.android.hardening.audit.LegacyPluginDeclarationCodec
import com.holin.android.hardening.audit.LegacyPluginObservationCodec
import com.holin.android.hardening.audit.RuntimeArtifactInputCodec
import com.holin.android.hardening.audit.RuntimeDependencyFingerprinter
import com.holin.android.hardening.code.CodeNamingManifestCodec
import com.holin.android.hardening.code.CodeNamingManifest
import com.holin.android.hardening.code.CodeSymbolKind
import com.holin.android.hardening.code.PotentialBeanFieldManifest
import com.holin.android.hardening.code.PotentialBeanFieldManifestCodec
import com.holin.android.hardening.inventory.AppOnlyMappingFilter
import com.holin.android.hardening.inventory.OwnedCodeOptimizationRules
import com.holin.android.hardening.inventory.OwnedDexInventoryBuilder
import com.holin.android.hardening.state.ArchiveMappingVerificationEvidence
import com.holin.android.hardening.state.ArchiveRequest
import com.holin.android.hardening.state.AtomicFiles
import com.holin.android.hardening.state.HardeningStateLockService
import com.holin.android.hardening.state.InvocationSaltService
import com.holin.android.hardening.state.PrepareRequest
import com.holin.android.hardening.state.PreparedState
import com.holin.android.hardening.state.PreparedStateCodec
import com.holin.android.hardening.state.PortableStateMigrationDescriptorLoader
import com.holin.android.hardening.state.ReproducibilityContext
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StateConfigurationMigrationRequest
import com.holin.android.hardening.state.StateCoordinates
import com.holin.android.hardening.state.StateStore
import com.holin.android.hardening.state.StrictJson
import com.holin.android.hardening.naming.RegistryCodec
import com.holin.android.hardening.verification.MappingContinuityVerifier
import com.holin.android.hardening.verification.MappingSymbolCounts
import com.holin.android.hardening.verification.MappingVerificationReport
import com.holin.android.hardening.verification.MappingVerificationReportCodec
import com.holin.android.hardening.verification.MappingVerificationStatus
import com.holin.android.hardening.verification.OfficialRetraceVerifier
import com.holin.android.hardening.verification.PotentialBeanFieldDexVerifier
import com.holin.android.hardening.verification.R8MappingParser
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault

@DisableCachingByDefault(because = "Hardening state is local, locked, and generation-CAS controlled")
abstract class PrepareHardeningTask : DefaultTask() {
    @get:Input abstract val projectKey: Property<String>
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val namespace: Property<String>
    @get:Input abstract val applicationId: Property<String>
    @get:Input abstract val configurationSchema: Property<String>
    @get:Input
    @get:Optional
    abstract val reproducibilityConfigurationSha256: Property<String>
    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val hardeningRules: RegularFileProperty
    @get:Input abstract val reusePrevious: Property<Boolean>
    @get:Input abstract val keepHistory: Property<Boolean>
    @get:Input abstract val quarantineInvalid: Property<Boolean>
    @get:Input abstract val autoMigrateLegacyState: Property<Boolean>
    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val migrationDescriptor: RegularFileProperty
    @get:Internal abstract val mappingStoreDirectory: DirectoryProperty
    @get:Internal abstract val repositoryRoot: DirectoryProperty
    @get:Internal abstract val ownership: Property<HardeningOwnership>
    @get:OutputDirectory abstract val preparedDirectory: DirectoryProperty
    @get:OutputFile abstract val appOnlyPreviousMapping: RegularFileProperty
    @get:OutputFile abstract val applyMappingRules: RegularFileProperty
    @get:Internal abstract val lockService: Property<HardeningStateLockService>
    @get:Internal abstract val saltService: Property<InvocationSaltService>

    init {
        autoMigrateLegacyState.convention(false)
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun prepare() {
        val output = preparedDirectory.get().asFile.toPath()
        deleteTaskOutput(output)
        val root = mappingStoreDirectory.get().asFile.toPath()
            .resolve(projectKey.get())
            .resolve(variantName.get())
        val coordinates = StateCoordinates(
            projectKey.get(),
            variantName.get(),
            namespace.get(),
            applicationId.get(),
            hardeningRulesFingerprint(hardeningRules, configurationSchema.get()),
        )
        val invocationSalt = saltService.get()
        invocationSalt.bind(
            ReproducibilityContext(
                coordinates.projectKey,
                coordinates.variant,
                reproducibilityConfigurationSha256.orNull ?: coordinates.configurationSha256,
            ),
        )
        val prepared = lockService.get().withLock {
            val store = StateStore()
            if (autoMigrateLegacyState.get()) {
                val migration = PortableStateMigrationDescriptorLoader.load(
                    repositoryRoot.get().asFile.toPath(),
                    migrationDescriptor.get().asFile.toPath(),
                    projectKey.get(),
                    variantName.get(),
                )
                store.migrateConfiguration(
                    StateConfigurationMigrationRequest(
                        root,
                        coordinates,
                        migration.state,
                    ),
                )
            }
            store.prepare(
                PrepareRequest(
                    root,
                    coordinates,
                    output,
                    invocationSalt.sha256(),
                    reusePrevious.get(),
                    keepHistory.get(),
                    quarantineInvalid.get(),
                    invocationSalt.stateReproducibility(),
                ),
            )
        }
        PreparedStateCodec.write(output.resolve(PREPARED_STATE_FILE), prepared)
        val fullMappingPath = output.resolve("mapping.txt")
        val fullMapping = Files.readString(fullMappingPath)
        val filteredMapping = AppOnlyMappingFilter(repositoryRoot.get().asFile.toPath(), ownership.get())
            .filter(fullMapping)
        val appOnlyMappingPath = appOnlyPreviousMapping.get().asFile.toPath()
        Files.createDirectories(requireNotNull(appOnlyMappingPath.parent))
        Files.writeString(appOnlyMappingPath, filteredMapping)
        val rules = buildString {
            if (filteredMapping.isBlank()) {
                append("# No reusable app-owned R8 mapping exists for this lineage.\n")
            } else {
                append("-applymapping ${quoteProguardPath(appOnlyMappingPath)}\n")
            }
            append('\n')
            append(
                OwnedCodeOptimizationRules(repositoryRoot.get().asFile.toPath(), ownership.get())
                    .render(),
            )
        }
        val rulesPath = applyMappingRules.get().asFile.toPath()
        Files.createDirectories(requireNotNull(rulesPath.parent))
        Files.writeString(rulesPath, rules)
    }

    private fun quoteProguardPath(path: Path): String = buildString {
        append('"')
        path.toAbsolutePath().normalize().toString().forEach { character ->
            if (character == '\\' || character == '"') append('\\')
            append(character)
        }
        append('"')
    }

    private fun deleteTaskOutput(path: Path) {
        if (!Files.exists(path)) return
        Files.walk(path).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }
}

@DisableCachingByDefault(because = "The audit reads local production sources, resolved artifacts, and plugin compatibility state")
abstract class AuditHardeningTask : DefaultTask() {
    @get:Input abstract val fullAuditEnabled: Property<Boolean>
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val namespace: Property<String>
    @get:Input abstract val unresolvedAppReflectionPolicy: Property<String>
    @get:Input abstract val unresolvedResourceLookupPolicy: Property<String>
    @get:Input abstract val externalNamesPolicy: Property<String>
    @get:Internal abstract val repositoryRoot: DirectoryProperty
    @get:Internal abstract val appDirectory: DirectoryProperty
    @get:Internal abstract val ownership: Property<HardeningOwnership>
    @get:Internal
    abstract val appStaticResourceDirectories: ListProperty<org.gradle.api.file.Directory>
    @get:Internal abstract val appStaticResourceLayerDirectoryCounts: ListProperty<Int>
    @get:Input abstract val appStaticResourceLayerIdentity: ListProperty<String>
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val appStaticResourceInputs: ConfigurableFileCollection
    @get:Input abstract val runtimeArtifactMetadata: ListProperty<String>
    @get:Input abstract val legacyPluginObservations: ListProperty<String>
    @get:Input abstract val legacyPluginDeclarations: ListProperty<String>
    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val legacyPluginsBaseline: RegularFileProperty
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val legacyPluginConfigurationInputs: ConfigurableFileCollection
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val runtimeClasspath: ConfigurableFileCollection

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val r8RulesManifest: RegularFileProperty
    @get:OutputFile abstract val auditReport: RegularFileProperty

    init {
        outputs.upToDateWhen { false }
        appStaticResourceDirectories.convention(emptyList())
        appStaticResourceLayerDirectoryCounts.convention(emptyList())
        appStaticResourceLayerIdentity.convention(emptyList())
    }

    @TaskAction
    fun audit() {
        val r8Hash = if (r8RulesManifest.isPresent) {
            val manifest = r8RulesManifest.get().asFile.toPath()
            require(Files.size(manifest) in 1..MAX_RULE_MANIFEST_BYTES) {
                "hardening R8 rule decision manifest has an invalid size"
            }
            StrictJson.validateDocument(Files.readString(manifest))
            logger.lifecycle("Hardening R8 rule decisions: ${project.relativePath(manifest.toFile())}")
            Sha256.file(manifest)
        } else {
            "0".repeat(64)
        }

        val sourceAudit = if (fullAuditEnabled.get()) {
            HardeningSourceAuditScanner(
                repositoryRoot.get().asFile.toPath(),
                appDirectory.get().asFile.toPath(),
                namespace.get(),
                appStaticResourceLayers(),
                ownership.get(),
            ).scan()
        } else {
            com.holin.android.hardening.audit.HardeningSourceAudit(emptyList(), emptyList(), emptyList(), emptyList())
        }
        val pluginObservations = legacyPluginObservations.get().map(LegacyPluginObservationCodec::decode)
        val pluginDeclarations = legacyPluginDeclarations.get().map(LegacyPluginDeclarationCodec::decode)
        val legacy = if (fullAuditEnabled.get()) {
            LegacyPluginBaselineVerifier.verifyRequired(
                legacyPluginsBaseline.orNull?.asFile?.toPath(),
                repositoryRoot.get().asFile.toPath(),
                pluginObservations,
                pluginDeclarations,
            )
        } else {
            LegacyCompatibilityVerifier.verify(pluginObservations, pluginDeclarations)
        }
        val runtimeInputs = runtimeArtifactMetadata.get().map(RuntimeArtifactInputCodec::decode)
        val metadataFiles = runtimeInputs.map { it.file.toAbsolutePath().normalize() }.toSet()
        val inputFiles = runtimeClasspath.files.map { it.toPath().toAbsolutePath().normalize() }.toSet()
        require(metadataFiles == inputFiles) { "release runtime dependency metadata does not match resolved files" }
        val dependencies = RuntimeDependencyFingerprinter().fingerprint(runtimeInputs)
        val violations = buildList {
            sourceAudit.unresolvedContracts.forEach { contract ->
                when (contract.kind) {
                    com.holin.android.hardening.audit.UnresolvedContractKind.APP_REFLECTION ->
                        if (unresolvedAppReflectionPolicy.get() == "FAIL_BUILD") {
                            add("${contract.sourceFile}:${contract.line}: unresolved app reflection: ${contract.reason}")
                        }
                    com.holin.android.hardening.audit.UnresolvedContractKind.RESOURCE_LOOKUP ->
                        if (unresolvedResourceLookupPolicy.get() == "FAIL_BUILD") {
                            add("${contract.sourceFile}:${contract.line}: unresolved resource lookup: ${contract.reason}")
                        }
                    com.holin.android.hardening.audit.UnresolvedContractKind.GSON_FIELD_NAMING_STRATEGY ->
                        add("${contract.sourceFile}:${contract.line}: unresolved Gson field naming: ${contract.reason}")
                    }
            }
            addAll(hardcodedReferenceViolations(ownership.get().hardcodedReferences, sourceAudit))
            if (legacy.status == LegacyCompatibilityStatus.FAIL) addAll(legacy.issues)
        }.sorted()
        require(externalNamesPolicy.get() == "PRESERVE_AND_REPORT") {
            "unsupported external name contract policy ${externalNamesPolicy.get()}"
        }
        val hardcodedScope = ownership.get().hardcodedReferences
        val audit = HardeningAuditReport(
            variantName.get(),
            namespace.get(),
            if (violations.isEmpty()) HardeningAuditStatus.PASS else HardeningAuditStatus.FAIL,
            sourceAudit.productionSourceFiles,
            sourceAudit.resolvedContracts,
            sourceAudit.unresolvedContracts,
            sourceAudit.externalNameCandidates,
            legacy,
            dependencies,
            r8Hash,
            sourceAudit.webpDiversificationFiles,
            HardcodedReferenceScopeReport(
                hardcodedScope.kinds.map { it.name },
                hardcodedScope.includeGlobs.toList(),
                hardcodedScope.excludeGlobs.toList(),
                hardcodedScope.failOnUnresolvedOwnedReference,
            ),
            sourceAudit.hardcodedReferenceFindings,
            sourceAudit.unresolvedHardcodedReferences,
        )
        val reportPath = auditReport.get().asFile.toPath()
        AtomicFiles().replace(reportPath, HardeningAuditReportCodec.encode(audit).toByteArray(Charsets.UTF_8))
        logger.lifecycle("Hardening audit report: ${project.relativePath(reportPath.toFile())}")
        if (violations.isNotEmpty()) {
            throw GradleException("Hardening audit failed:\n${violations.joinToString("\n") { "- $it" }}")
        }
    }

    private companion object {
        const val MAX_RULE_MANIFEST_BYTES = 4 * 1024 * 1024L
    }

    private fun appStaticResourceLayers(): List<List<Path>>? {
        if (appStaticResourceLayerIdentity.get().isEmpty()) return null
        val directories = appStaticResourceDirectories.get().map { directory ->
            directory.asFile.toPath().toAbsolutePath().normalize()
        }
        val counts = appStaticResourceLayerDirectoryCounts.get()
        require(counts.all { it >= 0 } && counts.sum() == directories.size) {
            "static app resource layer identity does not match selected directories"
        }
        var start = 0
        return counts.map { count ->
            directories.subList(start, start + count).also { start += count }
        }
    }
}

internal fun hardcodedReferenceViolations(
    scope: com.holin.android.hardening.HardeningOwnership.HardcodedReferenceScope,
    sourceAudit: HardeningSourceAudit,
): List<String> {
    if (!scope.failOnUnresolvedOwnedReference) return emptyList()
    return sourceAudit.unresolvedHardcodedReferences.map { finding ->
        "${finding.sourceFile}:${finding.line}: unresolved hardcoded reference " +
            "${finding.kind.name}: ${finding.reason}"
    }.sorted()
}

@DisableCachingByDefault(because = "The skeleton participates only in an opted-in hardening invocation")
abstract class VerifyHardeningTask : DefaultTask() {
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val namespace: Property<String>
    @get:Internal abstract val repositoryRoot: DirectoryProperty
    @get:Internal abstract val ownership: Property<HardeningOwnership>
    @get:Internal abstract val artifactBoundary: DirectoryProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val preparedState: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val previousAppOnlyMapping: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val codeNamingManifest: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val potentialBeanFieldsManifest: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val currentR8Mapping: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val preparedR8Mapping: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val hardenedBundle: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val transformationReport: RegularFileProperty

    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val bundleVerificationReport: RegularFileProperty

    @get:OutputFile abstract val mappingVerificationReport: RegularFileProperty

    init {
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun verify() {
        require(codeNamingManifest.isPresent) {
            "hardening verification requires a code naming manifest"
        }
        require(potentialBeanFieldsManifest.isPresent) {
            "hardening verification requires a potential Bean fields manifest"
        }
        val inputsWired = previousAppOnlyMapping.isPresent && currentR8Mapping.isPresent && preparedR8Mapping.isPresent &&
            hardenedBundle.isPresent && transformationReport.isPresent && bundleVerificationReport.isPresent
        if (!inputsWired) {
            val directlyRequested = project.gradle.startParameter.taskNames.any { requested ->
                requested.substringAfterLast(':') == name
            }
            require(!directlyRequested) { "verified hardening inputs were not wired for this Android variant" }
            return
        }
        val paths = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
        val previousMappingPath = paths.requireInput(previousAppOnlyMapping.get().asFile.toPath())
        val namingManifestPath = paths.requireInput(codeNamingManifest.get().asFile.toPath())
        val potentialBeanManifestPath = paths.requireInput(potentialBeanFieldsManifest.get().asFile.toPath())
        val currentMappingPath = paths.requireInput(currentR8Mapping.get().asFile.toPath())
        val preparedMappingPath = paths.requireInput(preparedR8Mapping.get().asFile.toPath())
        val hardenedAabPath = paths.requireInput(hardenedBundle.get().asFile.toPath())
        val transformationPath = paths.requireInput(transformationReport.get().asFile.toPath())
        val bundleReportPath = paths.requireInput(bundleVerificationReport.get().asFile.toPath())
        val reportPath = paths.prepareOutput(mappingVerificationReport.get().asFile.toPath())
        var namingManifest = CodeNamingManifestCodec().decode(Files.readString(namingManifestPath))
        var potentialBeanManifest = PotentialBeanFieldManifestCodec().decode(
            Files.readString(potentialBeanManifestPath),
        )
        require(namingManifest.variant == variantName.get()) { "code naming manifest variant mismatch" }
        require(namingManifest.ownedModules == ownership.get().modulePaths) { "code naming module scope mismatch" }
        require(namingManifest.mappingSha256 == Sha256.file(previousMappingPath)) {
            "code naming mapping hash mismatch"
        }
        require(namingManifest.expectedSymbols.isNotEmpty()) {
            "code naming manifest has no expected symbols"
        }
        require(potentialBeanManifest.variant == variantName.get()) { "potential Bean field manifest variant mismatch" }
        require(potentialBeanManifest.ownedModules == ownership.get().modulePaths) {
            "potential Bean field module scope mismatch"
        }
        require(preparedState.isPresent) { "hardening verification requires prepared state" }
        val prepared = PreparedStateCodec.read(paths.requireInput(preparedState.get().asFile.toPath()))
        val committedGeneration = StateStore().committedGeneration(prepared, Sha256.file(hardenedAabPath))
        normalizeCommittedGeneration(
            prepared,
            committedGeneration,
            namingManifestPath,
            potentialBeanManifestPath,
            transformationPath,
        )
        namingManifest = CodeNamingManifestCodec().decode(Files.readString(namingManifestPath))
        potentialBeanManifest = PotentialBeanFieldManifestCodec().decode(Files.readString(potentialBeanManifestPath))
        require(potentialBeanManifest.generation == namingManifest.generation) {
            "potential Bean field manifest generation differs from the code naming manifest"
        }
        val ownedDescriptors = OwnedDexInventoryBuilder(
            repositoryRoot.get().asFile.toPath(),
            ownership.get(),
        ).sourceInventory().mapTo(linkedSetOf()) { source -> source.originalDescriptor }
        val parser = R8MappingParser()
        val previous = parser.parse(previousMappingPath, ownedOriginalDescriptors = null)
        val completeCurrent = parser.parse(currentMappingPath, null)
        val current = parser.parse(currentMappingPath, ownedDescriptors)
        require(current.symbols.isNotEmpty()) { "current R8 mapping contains no app-owned symbols" }
        val continuity = MappingContinuityVerifier().verify(previous, current)

        val bundleReport = BundleVerificationReportCodec.decode(Files.readString(bundleReportPath))
        val transformation = HardenedBundlePlanReportCodec.decode(Files.readString(transformationPath))
        val previousHash = Sha256.file(previousMappingPath)
        val currentHash = Sha256.file(currentMappingPath)
        val preparedHash = Sha256.file(preparedMappingPath)
        val activeMappingHash = if (prepared.expectedGeneration == 0L) {
            currentHash
        } else {
            prepared.identity.payloadHashes.getValue("mapping.txt")
        }
        val hardenedHash = Sha256.file(hardenedAabPath)
        val violations = mutableListOf<String>()
        if (current.compiler != "R8") violations += "current mapping was not produced by R8"
        val currentCompilerVersion = current.compilerVersion
        if (currentCompilerVersion.isNullOrBlank()) {
            violations += "current mapping R8 compiler version is missing"
        }
        if (currentHash != preparedHash) {
            violations += "prepared mapping differs from the current AGP R8 mapping"
        }
        if (bundleReport.variant != variantName.get()) {
            violations += "bundle verification report variant differs from the selected variant"
        }
        if (bundleReport.hardenedAabSha256 != hardenedHash) {
            violations += "hardened AAB differs from the bundle verification report"
        }
        if (bundleReport.ordinaryAabSha256 != transformation.sourceAabSha256) {
            violations += "transformation and bundle reports identify different ordinary AABs"
        }
        if (bundleReport.contentSaltSha256 != transformation.contentSaltSha256) {
            violations += "transformation and bundle reports belong to different invocations"
        }
        if (
            bundleReport.fixedSeedProvided != transformation.fixedSeedProvided ||
            bundleReport.fixedSeedHash != transformation.fixedSeedHash
        ) {
            violations += "transformation and bundle reports have different reproducibility identities"
        }
        if (transformation.namespace != namespace.get()) {
            violations += "transformation report namespace differs from the selected variant"
        }
        if (continuity.mismatches.isNotEmpty()) {
            violations += "${continuity.mismatches.size} surviving expected symbols changed obfuscated names"
        }
        val potentialBeanFields = PotentialBeanFieldDexVerifier().verify(
            hardenedAabPath,
            completeCurrent,
            potentialBeanManifest,
        )
        violations += potentialBeanFields.violations

        val retraceVerifier = OfficialRetraceVerifier()
        val retraceCandidate = runCatching { retraceVerifier.selectCandidate(current) }
            .onFailure { failure -> violations += failure.message ?: "Retrace candidate selection failed" }
            .getOrNull()
        val retrace = retraceCandidate?.let { candidate ->
            currentCompilerVersion?.takeIf(String::isNotBlank)?.let { compilerVersion ->
                retraceVerifier.verify(currentMappingPath, candidate, compilerVersion)
            }
        }
        if (retrace == null || !retrace.verified) {
            violations += "official R8 Retrace did not restore the original app class, method, and line"
            retrace?.diagnostics?.let(violations::addAll)
        }
        val r8Version = retrace?.r8Version ?: retraceVerifier.runtimeVersion()
        val distinctViolations = violations.distinct().sorted()
        val status = if (distinctViolations.isEmpty()) MappingVerificationStatus.PASS else MappingVerificationStatus.FAIL
        val renamedOwnedClasses = namingManifest.expectedSymbols
            .count { assignment -> assignment.key.kind == CodeSymbolKind.CLASS }
        val renamedOwnedMethods = namingManifest.expectedSymbols
            .count { assignment -> assignment.key.kind == CodeSymbolKind.METHOD }
        val report = MappingVerificationReport(
            variantName.get(),
            status,
            r8Version,
            previousHash,
            activeMappingHash,
            currentHash,
            preparedHash,
            hardenedHash,
            Sha256.file(transformationPath),
            Sha256.file(bundleReportPath),
            bundleReport.ordinaryAabSha256,
            bundleReport.contentSaltSha256,
            Sha256.file(potentialBeanManifestPath),
            potentialBeanFields,
            renamedOwnedClasses,
            renamedOwnedMethods,
            potentialBeanManifest.retiredLegacyFieldAssignmentCount,
            MappingSymbolCounts.from(previous),
            MappingSymbolCounts.from(current),
            continuity,
            retraceCandidate?.obfuscatedFrame,
            retrace?.retracedFrames.orEmpty(),
            retrace?.verified == true,
            distinctViolations,
            bundleReport.fixedSeedProvided,
            bundleReport.fixedSeedHash,
        )
        AtomicFiles().replace(
            reportPath,
            MappingVerificationReportCodec.encode(report).toByteArray(Charsets.UTF_8),
        )
        paths.requireInput(reportPath)
        logger.lifecycle("Hardening mapping verification: ${project.relativePath(reportPath.toFile())}")
        if (status == MappingVerificationStatus.FAIL) {
            throw GradleException(
                "Hardening mapping verification failed: ${distinctViolations.joinToString("; ")}. " +
                    "See ${project.relativePath(reportPath.toFile())}",
            )
        }
    }

    private fun normalizeCommittedGeneration(
        prepared: PreparedState,
        generation: Long,
        namingManifestPath: Path,
        potentialBeanManifestPath: Path,
        transformationPath: Path,
    ) {
        if (generation == prepared.identity.generation) return
        val registry = RegistryCodec().decode(
            Files.readString(prepared.preparedDirectory.resolve("registry.json")),
        )
        val committedRegistry = StateStore().registryForCommittedGeneration(prepared, registry, generation)
        val naming = CodeNamingManifestCodec().decode(Files.readString(namingManifestPath))
        require(naming.generation == prepared.identity.generation) {
            "code naming manifest generation differs from prepared state"
        }
        val potentialBean = PotentialBeanFieldManifestCodec().decode(
            Files.readString(potentialBeanManifestPath),
        )
        require(potentialBean.generation == prepared.identity.generation) {
            "potential Bean field manifest generation differs from prepared state"
        }
        val transformation = HardenedBundlePlanReportCodec.decode(Files.readString(transformationPath))
        require(transformation.generation == prepared.identity.generation) {
            "transformation report generation differs from prepared state"
        }
        val normalizedNaming = CodeNamingManifest(
            naming.schemaVersion,
            naming.variant,
            generation,
            naming.ownedModules,
            naming.mappingSha256,
            codeNamingRegistrySha256(committedRegistry),
            naming.expectedSymbols,
            naming.exclusions,
        )
        val normalizedPotentialBean = PotentialBeanFieldManifest(
            potentialBean.schemaVersion,
            potentialBean.policyVersion,
            potentialBean.variant,
            generation,
            potentialBean.configurationSha256,
            potentialBean.inventorySha256,
            potentialBean.ownedModules,
            potentialBean.fields,
            potentialBean.retiredLegacyFieldAssignmentCount,
        )
        val normalizedTransformation = HardenedBundlePlanReport(
            transformation.schemaVersion,
            transformation.sourceAabSha256,
            transformation.contentSaltSha256,
            transformation.namespace,
            generation,
            transformation.ownedModules,
            transformation.dex,
            transformation.resources,
            transformation.fixedSeedProvided,
            transformation.fixedSeedHash,
        )
        val atomicFiles = AtomicFiles()
        atomicFiles.replace(
            namingManifestPath,
            CodeNamingManifestCodec().encode(normalizedNaming).toByteArray(Charsets.UTF_8),
        )
        atomicFiles.replace(
            potentialBeanManifestPath,
            PotentialBeanFieldManifestCodec().encode(normalizedPotentialBean).toByteArray(Charsets.UTF_8),
        )
        atomicFiles.replace(
            transformationPath,
            HardenedBundlePlanReportCodec.encode(normalizedTransformation).toByteArray(Charsets.UTF_8),
        )
    }
}

@DisableCachingByDefault(because = "Hardening state is local, locked, and generation-CAS controlled")
abstract class ArchiveHardeningTask : DefaultTask() {
    @get:Input abstract val projectKey: Property<String>
    @get:Input abstract val versionCode: Property<Int>
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val namespace: Property<String>
    @get:Input abstract val applicationId: Property<String>
    @get:Input abstract val configurationSchema: Property<String>
    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val hardeningRules: RegularFileProperty
    @get:Internal abstract val mappingStoreDirectory: DirectoryProperty
    @get:Internal abstract val preparedDirectory: DirectoryProperty
    @get:Internal abstract val artifactBoundary: DirectoryProperty
    @get:Internal abstract val ownership: Property<HardeningOwnership>
    @get:Internal abstract val lockService: Property<HardeningStateLockService>
    @get:Internal abstract val saltService: Property<InvocationSaltService>
    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val hardenedBundle: RegularFileProperty
    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val verificationReport: RegularFileProperty
    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val mappingVerificationReport: RegularFileProperty
    @get:InputFile
    @get:Optional
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val potentialBeanFieldsManifest: RegularFileProperty
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val auditReport: RegularFileProperty
    @get:OutputFile abstract val publishedBundle: RegularFileProperty
    @get:OutputFile abstract val publishedReport: RegularFileProperty
    @get:OutputFile abstract val publishedMappingVerificationReport: RegularFileProperty

    init {
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun archive() {
        val prepared = PreparedStateCodec.read(preparedDirectory.get().asFile.toPath().resolve(PREPARED_STATE_FILE))
        validatePreparedHandoff(prepared)
        require(prepared.contentSaltSha256 == saltService.get().sha256()) {
            "prepared content salt hash differs from the current Gradle invocation"
        }
        lockService.get().withLock {
            require(hardenedBundle.isPresent && verificationReport.isPresent) {
                "verified hardened AAB was not wired for this Android variant"
            }
            require(mappingVerificationReport.isPresent) {
                "verified hardening mapping report was not wired for this Android variant"
            }
            require(potentialBeanFieldsManifest.isPresent) {
                "hardening archive requires a potential Bean fields manifest"
            }
            val paths = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
            val hardenedAab = paths.requireInput(hardenedBundle.get().asFile.toPath())
            val stagedReport = paths.requireInput(verificationReport.get().asFile.toPath())
            val stagedMappingReport = paths.requireInput(mappingVerificationReport.get().asFile.toPath())
            val stagedPotentialBeanManifest = if (potentialBeanFieldsManifest.isPresent) {
                paths.requireInput(potentialBeanFieldsManifest.get().asFile.toPath())
            } else {
                null
            }
            val stagedAuditReport = paths.requireInput(auditReport.get().asFile.toPath())
            require(Files.size(stagedReport) in 1..MAX_VERIFICATION_REPORT_BYTES) {
                "hardening bundle verification report has an invalid size"
            }
            require(Files.size(stagedMappingReport) in 1..MAX_MAPPING_VERIFICATION_REPORT_BYTES) {
                "hardening mapping verification report has an invalid size"
            }
            if (stagedPotentialBeanManifest != null) {
                require(Files.size(stagedPotentialBeanManifest) in 1..MAX_POTENTIAL_BEAN_MANIFEST_BYTES) {
                    "potential Bean field manifest has an invalid size"
                }
            }
            require(Files.size(stagedAuditReport) in 1..MAX_AUDIT_REPORT_BYTES) {
                "hardening audit report has an invalid size"
            }
            HardeningAuditReportCodec.requirePassing(Files.readString(stagedAuditReport))
            val report = BundleVerificationReportCodec.decode(Files.readString(stagedReport))
            val hardenedAabHash = Sha256.file(hardenedAab)
            val stateStore = StateStore()
            val committedGeneration = stateStore.committedGeneration(prepared, hardenedAabHash)
            val potentialBeanManifest = stagedPotentialBeanManifest?.let { manifestPath ->
                PotentialBeanFieldManifestCodec().decode(Files.readString(manifestPath)).also { manifest ->
                    require(manifest.variant == variantName.get()) { "potential Bean field manifest variant mismatch" }
                    require(manifest.ownedModules == ownership.get().modulePaths) {
                        "potential Bean field module scope mismatch"
                    }
                    require(manifest.generation == committedGeneration) {
                        "potential Bean field manifest generation differs from the committed state"
                    }
                    require(manifest.configurationSha256 == prepared.coordinates.configurationSha256) {
                        "potential Bean field manifest configuration differs from prepared state"
                    }
                }
            }
            val mappingProvenance = MappingVerificationReportCodec.decodePassingProvenance(
                Files.readString(stagedMappingReport),
                stagedPotentialBeanManifest?.let(Sha256::file)
                    ?: "0".repeat(64),
                potentialBeanManifest
                    ?.retiredLegacyFieldAssignmentCount
                    ?: 0,
            )
            val preparedMappingPath = paths.requireInput(
                preparedDirectory.get().asFile.toPath().resolve("mapping.txt"),
            )
            val preparedMappingHash = Sha256.file(preparedMappingPath)
            val preparedMapping = R8MappingParser().parse(preparedMappingPath, null)
            require(preparedMapping.compiler == "R8") { "prepared mapping was not produced by R8" }
            val preparedMappingR8Version = requireNotNull(preparedMapping.compilerVersion) {
                "prepared mapping R8 compiler version is missing"
            }
            require(preparedMappingR8Version.isNotBlank()) {
                "prepared mapping R8 compiler version is missing"
            }
            require(report.variant == variantName.get()) { "hardening bundle verification report variant mismatch" }
            require(report.contentSaltSha256 == prepared.contentSaltSha256) {
                "hardening bundle verification report belongs to a different invocation"
            }
            require(
                report.fixedSeedProvided == (prepared.identity.fixedSeedSha256 != null) &&
                    report.fixedSeedHash == prepared.identity.fixedSeedSha256,
            ) {
                "hardening bundle verification report has a different reproducibility identity"
            }
            require(report.hardenedAabSha256 == hardenedAabHash) {
                "verified hardened AAB hash differs from its report"
            }
            require(mappingProvenance.variant == variantName.get()) {
                "hardening mapping verification report variant mismatch"
            }
            require(mappingProvenance.r8Version == preparedMappingR8Version) {
                "hardening mapping verification report R8 version differs from the prepared mapping"
            }
            require(mappingProvenance.preparedMappingSha256 == preparedMappingHash) {
                "hardening mapping verification report differs from the prepared mapping"
            }
            require(mappingProvenance.hardenedAabSha256 == hardenedAabHash) {
                "hardening mapping verification report identifies a different AAB"
            }
            require(mappingProvenance.bundleVerificationReportSha256 == Sha256.file(stagedReport)) {
                "hardening mapping verification report identifies a different bundle report"
            }
            require(mappingProvenance.ordinaryAabSha256 == report.ordinaryAabSha256) {
                "hardening mapping and bundle reports identify different ordinary AABs"
            }
            require(mappingProvenance.contentSaltSha256 == prepared.contentSaltSha256) {
                "hardening mapping verification report belongs to a different invocation"
            }
            require(
                mappingProvenance.fixedSeedProvided == report.fixedSeedProvided &&
                    mappingProvenance.fixedSeedHash == report.fixedSeedHash,
            ) {
                "hardening mapping and bundle reports have different reproducibility identities"
            }
            require(
                mappingProvenance.fixedSeedProvided == (prepared.identity.fixedSeedSha256 != null) &&
                    mappingProvenance.fixedSeedHash == prepared.identity.fixedSeedSha256,
            ) {
                "hardening mapping verification report has a different reproducibility identity"
            }
            VerifiedArtifactPublisher().publish(
                listOf(
                    VerifiedArtifactPublisher.Publication(
                        hardenedAab,
                        paths.prepareOutput(publishedBundle.get().asFile.toPath()),
                    ),
                    VerifiedArtifactPublisher.Publication(
                        stagedReport,
                        paths.prepareOutput(publishedReport.get().asFile.toPath()),
                    ),
                    VerifiedArtifactPublisher.Publication(
                        stagedMappingReport,
                        paths.prepareOutput(publishedMappingVerificationReport.get().asFile.toPath()),
                    ),
                ),
            ) {
                stateStore.archive(
                    ArchiveRequest(
                        prepared,
                        versionCode.get(),
                        hardenedAabHash,
                        ArchiveMappingVerificationEvidence(hardenedAab, stagedMappingReport),
                    ),
                )
            }
            paths.requireInput(publishedBundle.get().asFile.toPath())
            paths.requireInput(publishedReport.get().asFile.toPath())
            paths.requireInput(publishedMappingVerificationReport.get().asFile.toPath())
        }
    }

    private fun validatePreparedHandoff(prepared: com.holin.android.hardening.state.PreparedState) {
        val expectedRoot = mappingStoreDirectory.get().asFile.toPath()
            .resolve(projectKey.get())
            .resolve(variantName.get())
        PreparedHandoffValidator.validate(
            prepared = prepared,
            expectedRoot = expectedRoot,
            expectedPreparedDirectory = preparedDirectory.get().asFile.toPath(),
            expectedCoordinates = StateCoordinates(
                projectKey.get(),
                variantName.get(),
                namespace.get(),
                applicationId.get(),
                hardeningRulesFingerprint(hardeningRules, configurationSchema.get()),
            ),
        )
    }

    private companion object {
        const val MAX_VERIFICATION_REPORT_BYTES = 16 * 1024L
        const val MAX_MAPPING_VERIFICATION_REPORT_BYTES = 4 * 1024 * 1024L
        const val MAX_POTENTIAL_BEAN_MANIFEST_BYTES = 16 * 1024 * 1024L
        const val MAX_AUDIT_REPORT_BYTES = 32 * 1024 * 1024L
    }
}

private fun hardeningRulesFingerprint(rules: RegularFileProperty, schema: String): String {
    val rulesHash = if (rules.isPresent) {
        Sha256.file(rules.get().asFile.toPath())
    } else {
        Sha256.hex(ByteArray(0))
    }
    return Sha256.hex("$schema\n$rulesHash".toByteArray(Charsets.UTF_8))
}

@DisableCachingByDefault(because = "This is an explicit opt-in lifecycle entrypoint")
abstract class HardeningEntryTask : DefaultTask() {
    @get:Input abstract val hardeningEnabled: Property<Boolean>
    @get:Input abstract val correctedCommand: Property<String>
    @get:Internal
    abstract val expectedArtifact: RegularFileProperty

    @TaskAction
    fun enter() {
        if (!hardeningEnabled.get()) {
            throw GradleException("Android hardening is disabled. Run exactly:\n${correctedCommand.get()}")
        }
        if (expectedArtifact.isPresent && !expectedArtifact.get().asFile.isFile) {
            throw GradleException("The verified hardened artifact was not produced")
        }
    }
}

@DisableCachingByDefault(because = "Benchmark reporting is an explicit hardening lifecycle action")
abstract class BenchmarkHardeningTask : DefaultTask() {
    @TaskAction fun benchmark() = Unit
}

internal const val PREPARED_STATE_FILE = "prepared-state.properties"
