package com.holin.android.hardening.tasks

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.audit.HardeningSourceAuditScanner
import com.holin.android.hardening.code.BytecodeInput
import com.holin.android.hardening.code.ClassArtifactInput
import com.holin.android.hardening.code.ClassArtifactInputCodec
import com.holin.android.hardening.code.CodeNameAllocator
import com.holin.android.hardening.code.CodeNamePlan
import com.holin.android.hardening.code.CodeNamingManifest
import com.holin.android.hardening.code.CodeNamingManifestCodec
import com.holin.android.hardening.code.CoordinatorLayoutBehaviorRulesRenderer
import com.holin.android.hardening.code.HardcodedMemberKeepNamesRulesRenderer
import com.holin.android.hardening.code.OwnedBytecodeInventoryBuilder
import com.holin.android.hardening.code.OwnedCodeContractClassifier
import com.holin.android.hardening.code.PotentialBeanField
import com.holin.android.hardening.code.PotentialBeanFieldManifest
import com.holin.android.hardening.code.PotentialBeanFieldManifestCodec
import com.holin.android.hardening.code.PotentialBeanFieldPolicy
import com.holin.android.hardening.code.PotentialBeanFieldRulesRenderer
import com.holin.android.hardening.code.ProgramDescriptorPackageNamesRulesRenderer
import com.holin.android.hardening.code.R8CodeMappingRenderer
import com.holin.android.hardening.code.SerializableKeepNamesRulesRenderer
import com.holin.android.hardening.code.fieldRegistryIdentity
import com.holin.android.hardening.inventory.OwnedCodeOptimizationRules
import com.holin.android.hardening.naming.PseudowordRegistry
import com.holin.android.hardening.naming.RegistryCodec
import com.holin.android.hardening.naming.RegistrySnapshot
import com.holin.android.hardening.naming.SymbolKind
import com.holin.android.hardening.state.AtomicFiles
import com.holin.android.hardening.state.PreparedStateCodec
import com.holin.android.hardening.state.Sha256
import java.nio.file.Files
import java.nio.file.Path
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.Directory
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.FileCollection
import org.gradle.api.file.RegularFile
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.CacheableTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction

@CacheableTask
abstract class GenerateHardeningCodeMappingTask : DefaultTask() {
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val namespace: Property<String>
    @get:Input abstract val applicationModulePath: Property<String>
    @get:Input abstract val unresolvedAppReflectionPolicy: Property<String>
    @get:Input abstract val externalNamesPolicy: Property<String>
    @get:Internal abstract val repositoryRoot: DirectoryProperty
    @get:Internal abstract val ownership: Property<HardeningOwnership>
    @get:Input abstract val ownedArtifactMetadata: ListProperty<String>
    @get:Input abstract val hierarchyArtifactMetadata: ListProperty<String>
    @get:Internal
    abstract val appStaticResourceDirectories: ListProperty<Directory>
    @get:Internal abstract val appStaticResourceLayerDirectoryCounts: ListProperty<Int>
    @get:Input abstract val appStaticResourceLayerIdentity: ListProperty<String>
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val appStaticResourceInputs: ConfigurableFileCollection
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val projectClassJars: ListProperty<RegularFile>
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val projectClassDirectories: ListProperty<Directory>
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val runtimeClasspath: ConfigurableFileCollection
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val bootClasspath: ConfigurableFileCollection
    @get:Input
    val orderedBootClasspathIdentity: List<String>
        get() = bootClasspath.files.map { file -> Sha256.canonicalNode(normalized(file.toPath())) }
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val preparedRegistry: RegularFileProperty
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val lineageSeed: RegularFileProperty
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val preparedState: RegularFileProperty
    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val effectiveR8Rules: RegularFileProperty
    @get:OutputFile abstract val codeRegistry: RegularFileProperty
    @get:OutputFile abstract val codeMapping: RegularFileProperty
    @get:OutputFile abstract val applyMappingRules: RegularFileProperty
    @get:OutputFile abstract val codeNamingManifest: RegularFileProperty
    @get:OutputFile abstract val potentialBeanFieldsManifest: RegularFileProperty

    init {
        appStaticResourceDirectories.convention(emptyList())
        appStaticResourceLayerDirectoryCounts.convention(emptyList())
        appStaticResourceLayerIdentity.convention(emptyList())
    }

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    val sourceContractInputs: FileCollection
        get() {
            val root = repositoryRoot.get().asFile
            val resolvedOwnership = ownership.get()
            val codeTrees = resolvedOwnership.modules.flatMap { module ->
                (module.sourceRoots.javaDirectories + module.sourceRoots.kotlinDirectories).map { sourceRoot ->
                    project.fileTree(sourceRoot.toFile()) {
                        include("**/*.java", "**/*.kt")
                        exclude("**/*.kts", "**/build/**", "**/generated/**", "**/test/**", "**/androidTest/**", "**/testFixtures/**")
                    }
                }
            }
            val resourceTrees = resolvedOwnership.modules.flatMap { module ->
                module.sourceRoots.resourceDirectories.map { sourceRoot ->
                    project.fileTree(sourceRoot.toFile()) {
                        include("**/*")
                        exclude("**/build/**", "**/generated/**", "**/test/**", "**/androidTest/**", "**/testFixtures/**")
                    }
                }
            }
            val manifestFiles = resolvedOwnership.modules.flatMap { module -> module.sourceRoots.manifestFiles }
            val ignoreTrees = project.fileTree(root) {
                include("**/.gitignore")
                exclude(".gradle-home/**", "**/build/**")
            }
            val rootIgnoreFiles = listOf(root.resolve(".gitignore")) + gitIgnoreControlPaths.map(Path::of).map(Path::toFile)
            val existingIgnoreFiles = rootIgnoreFiles.filter { file -> file.isFile }
            return project.files(codeTrees, resourceTrees, manifestFiles, ignoreTrees, existingIgnoreFiles)
        }

    @get:Input
    val gitIgnoreControlPaths: List<String>
        get() = buildList {
            add(requireNotNull(gitPath(listOf("rev-parse", "--git-path", "info/exclude"))).toString())
            add(defaultGlobalGitIgnorePath().toString())
            gitPath(listOf("config", "--path", "--get", "core.excludesFile"), optional = true)?.let { add(it.toString()) }
        }.distinct().sorted()

    @get:Input
    val codeMappingOutputPath: String
        get() = codeMapping.get().asFile.toPath().toAbsolutePath().normalize().toString()

    @TaskAction
    fun generate() {
        val generated = createPlan()
        val plan = generated.plan
        val mapping = R8CodeMappingRenderer().render(plan)
        val registry = RegistryCodec().encode(plan.registry)
        val mappingPath = codeMapping.get().asFile.toPath()
        val registryPath = codeRegistry.get().asFile.toPath()
        val rulesPath = applyMappingRules.get().asFile.toPath()
        val manifestPath = codeNamingManifest.get().asFile.toPath()
        val potentialBeanFieldsManifestPath = potentialBeanFieldsManifest.get().asFile.toPath()
        val mappingSha256 = Sha256.hex(mapping.toByteArray(Charsets.UTF_8))
        val manifest = CodeNamingManifestCodec().encode(
            CodeNamingManifest(
                1,
                variantName.get(),
                plan.registry.generation,
                ownership.get().modulePaths,
                mappingSha256,
                codeNamingRegistrySha256(plan.registry),
                plan.assignments,
                plan.exclusions,
            ),
        )
        val fieldManifest = PotentialBeanFieldManifestCodec().encode(
            PotentialBeanFieldManifest(
                1,
                com.holin.android.hardening.code.POTENTIAL_BEAN_FIELD_POLICY_VERSION,
                variantName.get(),
                plan.registry.generation,
                generated.configurationSha256,
                generated.inventorySha256,
                ownership.get().modulePaths,
                generated.potentialBeanFields,
                generated.retiredLegacyFieldAssignmentCount,
            ),
        )
        val atomicFiles = AtomicFiles()
        atomicFiles.replace(mappingPath, mapping.toByteArray(Charsets.UTF_8))
        atomicFiles.replace(registryPath, registry.toByteArray(Charsets.UTF_8))
        atomicFiles.replace(rulesPath, applyRules(generated, mappingPath, mappingSha256).toByteArray(Charsets.UTF_8))
        atomicFiles.replace(manifestPath, manifest.toByteArray(Charsets.UTF_8))
        atomicFiles.replace(potentialBeanFieldsManifestPath, fieldManifest.toByteArray(Charsets.UTF_8))
    }

    private fun createPlan(): GeneratedCodePlan {
        require(unresolvedAppReflectionPolicy.get() == "FAIL_BUILD") {
            "unsupported unresolved app reflection policy ${unresolvedAppReflectionPolicy.get()}"
        }
        require(externalNamesPolicy.get() == "PRESERVE_AND_REPORT") {
            "unsupported external name contract policy ${externalNamesPolicy.get()}"
        }
        val root = repositoryRoot.get().asFile.toPath().toAbsolutePath().normalize()
        val owned = ownedArtifactMetadata.get().map(ClassArtifactInputCodec::decode)
        val hierarchy = hierarchyArtifactMetadata.get().map(ClassArtifactInputCodec::decode)
        validateArtifactInputs(owned, hierarchy)

        val registryPath = preparedRegistry.get().asFile.toPath().toAbsolutePath().normalize()
        val seedPath = lineageSeed.get().asFile.toPath().toAbsolutePath().normalize()
        val statePath = preparedState.get().asFile.toPath().toAbsolutePath().normalize()
        val state = PreparedStateCodec.read(statePath)
        val preparedRoot = state.preparedDirectory.toAbsolutePath().normalize()
        require(state.coordinates.variant == variantName.get()) { "prepared state variant differs from the selected variant" }
        require(state.coordinates.namespace == namespace.get()) { "prepared state namespace differs from the selected variant" }
        require(registryPath == preparedRoot.resolve("registry.json")) { "prepared registry does not match prepared state" }
        require(seedPath == preparedRoot.resolve("seed.bin")) { "lineage seed does not match prepared state" }
        require(statePath == preparedRoot.resolve(PREPARED_STATE_FILE)) { "prepared state file does not match its directory" }
        require(Sha256.file(registryPath) == state.identity.payloadHashes.getValue("registry.json")) {
            "prepared registry hash differs from prepared state"
        }
        require(Sha256.file(seedPath) == state.identity.seedHash) { "lineage seed hash differs from prepared state" }

        val seed = Files.readAllBytes(seedPath)
        return try {
            val registrySnapshot = RegistryCodec().decode(Files.readString(registryPath))
            require(registrySnapshot.seedSha256 == state.identity.seedHash) { "prepared registry belongs to another lineage" }
            require(registrySnapshot.generation == state.identity.generation) { "prepared registry generation differs from prepared state" }
            val bootPrecedence = bootClasspath.files.mapIndexed { index, file ->
                normalized(file.toPath()) to index
            }.toMap()
            val runtimePrecedence = bootPrecedence.size
            val bytecode = OwnedBytecodeInventoryBuilder(root, ownership.get()).build(
                (owned + hierarchy).map { input ->
                    BytecodeInput(
                        input.file,
                        input.modulePath,
                        hierarchyPrecedence = input.hierarchyPrecedence ?: bootPrecedence[normalized(input.file)],
                        programInput = input.modulePath != null || input.hierarchyPrecedence == runtimePrecedence,
                    )
                },
            )
            val sourceAudit = HardeningSourceAuditScanner(
                root,
                ownership.get().modules.single { module -> module.path == applicationModulePath.get() }.directory,
                namespace.get(),
                appStaticResourceLayers(),
                ownership.get(),
            ).scan()
            val potentialBeanFields = PotentialBeanFieldPolicy().inventory(bytecode)
            val rulesPath = effectiveR8Rules.get().asFile.toPath().toAbsolutePath().normalize()
            require(Files.isRegularFile(rulesPath) && !Files.isSymbolicLink(rulesPath)) {
                "effective R8 rules are missing or unsafe: $rulesPath"
            }
            val inventory = OwnedCodeContractClassifier().classify(
                bytecode,
                sourceAudit,
                potentialBeanFields,
                Files.readString(rulesPath),
            )
            val retiredLegacyFieldAssignmentCount = retiredLegacyFieldAssignmentCount(
                registrySnapshot,
                potentialBeanFields,
            )
            val fieldCodec = PotentialBeanFieldManifestCodec()
            GeneratedCodePlan(
                CodeNameAllocator(PseudowordRegistry.restore(seed, registrySnapshot)).allocate(
                    inventory = inventory,
                    bytecode = bytecode,
                    generation = state.identity.generation,
                ),
                bytecode.programClasses,
                potentialBeanFields,
                state.coordinates.configurationSha256,
                fieldCodec.inventorySha256(potentialBeanFields),
                retiredLegacyFieldAssignmentCount,
            )
        } finally {
            seed.fill(0)
        }
    }

    private fun validateArtifactInputs(
        owned: List<ClassArtifactInput>,
        hierarchy: List<ClassArtifactInput>,
    ) {
        require(owned.all { it.component.isNotBlank() && it.modulePath != null }) {
            "owned class artifact metadata is incomplete"
        }
        require(hierarchy.all { it.component.isNotBlank() && it.modulePath == null }) {
            "hierarchy class artifact metadata must identify external inputs"
        }
        val bootPaths = bootClasspath.files.mapTo(linkedSetOf()) { file -> normalized(file.toPath()) }
        require(hierarchy.all { input -> input.hierarchyPrecedence != null || normalized(input.file) in bootPaths }) {
            "non-boot hierarchy class artifact metadata requires explicit precedence"
        }
        require(owned.mapNotNull(ClassArtifactInput::modulePath).toSet() == ownership.get().modulePaths) {
            "owned class artifact modules do not match configured ownership"
        }
        val ownedPaths = normalizedMetadataPaths(owned, "owned")
        val hierarchyPaths = normalizedMetadataPaths(hierarchy, "hierarchy")
        require(ownedPaths.intersect(hierarchyPaths).isEmpty()) { "class artifact metadata contains duplicate paths" }

        val projectPaths = (
            projectClassJars.get().map { it.asFile.toPath() } +
                projectClassDirectories.get().map { it.asFile.toPath() }
            ).mapTo(linkedSetOf(), ::normalized)
        val hierarchyFiles = (runtimeClasspath.files + bootClasspath.files)
            .mapTo(linkedSetOf()) { file -> normalized(file.toPath()) }
        require(ownedPaths == projectPaths) { "owned class artifact metadata does not match the normalized Gradle file collection" }
        require(ownedPaths + hierarchyPaths == projectPaths + hierarchyFiles) {
            "class artifact metadata does not match the normalized Gradle file collection"
        }
    }

    private fun appStaticResourceLayers(): List<List<Path>> {
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

    private fun normalizedMetadataPaths(inputs: List<ClassArtifactInput>, label: String): Set<Path> {
        val paths = inputs.map { input -> normalized(input.file) }
        require(paths.distinct().size == paths.size) { "$label class artifact metadata contains duplicate paths" }
        return paths.toCollection(linkedSetOf())
    }

    private fun applyRules(generated: GeneratedCodePlan, mappingPath: Path, mappingSha256: String): String = buildString {
        val plan = generated.plan
        append("# hardening mapping sha256: ").append(mappingSha256).append('\n')
        append("-applymapping ").append(quoteProguardPath(mappingPath)).append('\n').append('\n')
        val potentialBeanFieldRules = PotentialBeanFieldRulesRenderer().render(
            generated.potentialBeanFields,
            plan.ownedOriginalOwners,
        )
        append(potentialBeanFieldRules)
        if (potentialBeanFieldRules.isNotEmpty()) append('\n')
        val serializableKeepNames = SerializableKeepNamesRulesRenderer().render(plan)
        append(serializableKeepNames)
        if (serializableKeepNames.isNotEmpty()) append('\n')
        val hardcodedMemberKeepNames = HardcodedMemberKeepNamesRulesRenderer().render(plan)
        append(hardcodedMemberKeepNames)
        if (hardcodedMemberKeepNames.isNotEmpty()) append('\n')
        val coordinatorLayoutBehaviorRules = CoordinatorLayoutBehaviorRulesRenderer().render(plan)
        append(coordinatorLayoutBehaviorRules)
        if (coordinatorLayoutBehaviorRules.isNotEmpty()) append('\n')
        val programDescriptorPackages = ProgramDescriptorPackageNamesRulesRenderer().render(
            plan,
            generated.programClasses,
        )
        append(programDescriptorPackages)
        if (programDescriptorPackages.isNotEmpty()) append('\n')
        append(OwnedCodeOptimizationRules(repositoryRoot.get().asFile.toPath(), ownership.get()).render())
    }

    private data class GeneratedCodePlan(
        val plan: CodeNamePlan,
        val programClasses: Set<String>,
        val potentialBeanFields: List<PotentialBeanField>,
        val configurationSha256: String,
        val inventorySha256: String,
        val retiredLegacyFieldAssignmentCount: Int,
    )

    private fun retiredLegacyFieldAssignmentCount(
        registry: RegistrySnapshot,
        fields: Collection<PotentialBeanField>,
    ): Int {
        val protectedRegistryKeys = fields.associate { field ->
            fieldRegistryIdentity(field.key) to field.key.descriptor
        }
        return registry.assignments.count { assignment ->
            assignment.key.kind == SymbolKind.MEMBER &&
                protectedRegistryKeys[assignment.key.originalIdentity] == assignment.key.descriptor
        }
    }

    private fun quoteProguardPath(path: Path): String = buildString {
        append('"')
        path.toAbsolutePath().normalize().toString().forEach { character ->
            if (character == '\\' || character == '"') append('\\')
            append(character)
        }
        append('"')
    }

    private fun normalized(path: Path): Path = path.toAbsolutePath().normalize()

    private fun defaultGlobalGitIgnorePath(): Path {
        val configRoot = System.getenv("XDG_CONFIG_HOME")?.takeIf(String::isNotBlank)?.let(Path::of)
            ?: Path.of(System.getProperty("user.home"), ".config")
        return configRoot.resolve("git/ignore").toAbsolutePath().normalize()
    }

    private fun gitPath(arguments: List<String>, optional: Boolean = false): Path? {
        val root = repositoryRoot.get().asFile.toPath().toAbsolutePath().normalize()
        val process = ProcessBuilder(listOf("git", "-C", root.toString()) + arguments)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.use { it.readBytes().toString(Charsets.UTF_8).trim() }
        val exitCode = process.waitFor()
        if (optional && exitCode == 1 && output.isEmpty()) return null
        require(exitCode == 0 && output.isNotEmpty()) {
            "git ${arguments.joinToString(" ")} failed with exit $exitCode: $output"
        }
        return Path.of(output).let { path -> if (path.isAbsolute) path else root.resolve(path) }
            .toAbsolutePath().normalize()
    }

    private companion object {
    }
}

internal fun codeNamingRegistrySha256(registry: RegistrySnapshot): String {
    val codeScope = RegistrySnapshot(
        registry.schemaVersion,
        registry.seedSha256,
        registry.generation,
        registry.assignments.filterNot { assignment -> assignment.key.kind == SymbolKind.RESOURCE },
        registry.tombstones.filterNot { tombstone -> tombstone.kind == SymbolKind.RESOURCE },
    )
    return Sha256.hex(RegistryCodec().encode(codeScope).toByteArray(Charsets.UTF_8))
}
