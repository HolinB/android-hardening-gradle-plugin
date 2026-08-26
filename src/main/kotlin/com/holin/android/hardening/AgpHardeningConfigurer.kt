package com.holin.android.hardening

import com.android.build.api.artifact.ScopedArtifact
import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.dsl.ApkSigningConfig
import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.dsl.BuildType
import com.android.build.api.dsl.ProductFlavor
import com.android.build.api.dsl.VariantDimension
import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import com.android.build.api.variant.ApplicationVariant
import com.android.build.api.variant.ScopedArtifacts
import com.holin.android.hardening.artifact.SigningMaterial
import com.holin.android.hardening.code.ClassArtifactInput
import com.holin.android.hardening.code.ClassArtifactInputCodec
import com.holin.android.hardening.inventory.AppStaticResourceDirectoryPolicy
import com.holin.android.hardening.tasks.ArchiveHardeningTask
import com.holin.android.hardening.tasks.AssembleHardeningUniversalApkTask
import com.holin.android.hardening.tasks.AuditHardeningTask
import com.holin.android.hardening.tasks.BenchmarkHardeningTask
import com.holin.android.hardening.tasks.GenerateHardeningCodeMappingTask
import com.holin.android.hardening.tasks.GenerateHardeningR8RulesTask
import com.holin.android.hardening.tasks.HardeningEntryTask
import com.holin.android.hardening.tasks.PrepareHardeningTask
import com.holin.android.hardening.tasks.PREPARED_STATE_FILE
import com.holin.android.hardening.tasks.RewriteHardeningBundleTask
import com.holin.android.hardening.tasks.ValidateHardeningBundleTask
import com.holin.android.hardening.tasks.VerifyHardeningTask
import com.holin.android.hardening.tasks.CaptureHardeningBaselineTask
import com.holin.android.hardening.tasks.CompareHardeningSimilarityTask
import com.holin.android.hardening.tasks.SmokeHardeningTask
import org.gradle.api.Project
import org.gradle.api.artifacts.component.ProjectComponentIdentifier
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.api.artifacts.type.ArtifactTypeDefinition
import org.gradle.api.file.Directory
import org.gradle.api.file.FileCollection
import org.gradle.api.file.RegularFile
import org.gradle.api.provider.Provider
import org.gradle.api.tasks.TaskProvider
import java.nio.file.Files
import java.nio.file.Path

internal data class AndroidVariantIdentityProviders(
    val namespace: Provider<String>,
    val applicationId: Provider<String>,
    val versionCode: Provider<Int>,
    val versionName: Provider<String>,
)

internal data class AgpVariantContext(
    val variantName: String,
    val identity: AndroidVariantIdentityProviders,
    val mergedManifest: Provider<RegularFile>?,
    val wiringEnabled: Boolean,
    val bundle: AgpBundleContext?,
)

internal data class AgpBundleContext(
    val ordinaryBundle: Provider<RegularFile>,
    val obfuscationMapping: Provider<RegularFile>,
    val signingMaterial: SigningMaterial,
)

internal data class HardeningVariantTasks(
    val prepare: TaskProvider<PrepareHardeningTask>,
    val audit: TaskProvider<AuditHardeningTask>,
    val verify: TaskProvider<VerifyHardeningTask>,
    val archive: TaskProvider<ArchiveHardeningTask>,
    val bundle: TaskProvider<HardeningEntryTask>,
    val assemble: TaskProvider<HardeningEntryTask>,
    val benchmark: TaskProvider<BenchmarkHardeningTask>,
    val captureBaseline: TaskProvider<CaptureHardeningBaselineTask>?,
    val compare: TaskProvider<CompareHardeningSimilarityTask>?,
    val smoke: TaskProvider<SmokeHardeningTask>?,
    val run: TaskProvider<HardeningEntryTask>?,
    val pipeline: HardeningBundlePipelineTasks?,
)

internal data class HardeningBundlePipelineTasks(
    val rewrite: TaskProvider<RewriteHardeningBundleTask>,
    val validate: TaskProvider<ValidateHardeningBundleTask>,
    val universalApk: TaskProvider<AssembleHardeningUniversalApkTask>,
)

internal object AgpHardeningConfigurer {
    fun configure(
        project: Project,
        extension: AndroidHardeningExtension,
        registerTasks: (AgpVariantContext) -> HardeningVariantTasks,
    ) {
        val androidComponents = project.extensions.getByType(ApplicationAndroidComponentsExtension::class.java)
        val hardeningEnabled = HardeningWiringGate.isEnabled(project.gradle.startParameter.projectProperties)
        var signingSnapshot: SigningDslSnapshot? = null
        if (hardeningEnabled) {
            androidComponents.finalizeDsl { android ->
                val requestedBuildTypes = HardeningWiringGate.requestedBuildTypes(
                    requestedTasks = project.gradle.startParameter.taskNames,
                    includedVariants = extension.variants.included.get(),
                    buildTypes = android.buildTypes.mapTo(linkedSetOf()) { buildType -> buildType.name },
                    projectPath = project.path,
                )
                if (requestedBuildTypes.isNotEmpty()) {
                    val conflictingTasks = HardeningWiringGate.conflictingProjectArtifactTasks(
                        requestedTasks = project.gradle.startParameter.taskNames,
                        includedVariants = extension.variants.included.get(),
                        projectPath = project.path,
                    )
                    require(conflictingTasks.isEmpty()) {
                        "Android hardening tasks for ${project.path} cannot be combined with other " +
                            "artifact-producing tasks in the same project invocation: $conflictingTasks"
                    }
                }
                requestedBuildTypes.forEach { buildTypeName ->
                    android.buildTypes.getByName(buildTypeName).apply {
                        val preserveDebugBuildConfig = isDebuggable
                        isMinifyEnabled = true
                        isDebuggable = false
                        if (preserveDebugBuildConfig) {
                            buildConfigField("boolean", "DEBUG", "true")
                        }
                    }
                }
                replaceSelectedVariantSourceRules(
                    android,
                    extension,
                    project.gradle.startParameter.taskNames,
                    project.path,
                )
                signingSnapshot = SigningDslSnapshot.capture(android)
            }
        }
        androidComponents.onVariants(androidComponents.selector().all()) { variant ->
            val included = extension.variants.included.get()
            if (!HardeningWiringGate.isSelected(variant.name, included)) return@onVariants
            val variantWiringEnabled = hardeningEnabled && HardeningWiringGate.isHardeningTaskRequested(
                variantName = variant.name,
                requestedTasks = project.gradle.startParameter.taskNames,
                projectPath = project.path,
            )
            val tasks = registerTasks(
                AgpVariantContext(
                    variant.name,
                    identityProviders(project, variant),
                    variant.artifacts.get(SingleArtifact.MERGED_MANIFEST),
                    variantWiringEnabled,
                    if (variantWiringEnabled) {
                        val finalizedSigning = requireNotNull(signingSnapshot) {
                            "Android signing DSL was not finalized before hardening variant wiring"
                        }
                        val bundleContext = AgpBundleContext(
                            ordinaryBundle = variant.artifacts.get(SingleArtifact.BUNDLE),
                            obfuscationMapping = variant.artifacts.get(SingleArtifact.OBFUSCATION_MAPPING_FILE),
                            signingMaterial = finalizedSigning.resolve(variant),
                        )
                        bundleContext
                    } else {
                        null
                    },
                ),
            )
            if (variantWiringEnabled) {
                val effectiveR8Rules = wireFilteredAppRules(project, extension, variant, tasks)
                wireStableCodeNaming(
                    project,
                    extension,
                    androidComponents,
                    variant,
                    tasks,
                    effectiveR8Rules,
                )
            }
        }
    }

    private fun wireStableCodeNaming(
        project: Project,
        extension: AndroidHardeningExtension,
        androidComponents: ApplicationAndroidComponentsExtension,
        variant: ApplicationVariant,
        tasks: HardeningVariantTasks,
        effectiveR8Rules: Provider<RegularFile>,
    ) {
        val resolvedOwnership = project.providers.provider { extension.ownership.resolve(project.rootProject) }
        val appStaticResourceSources = requireNotNull(variant.sources.res) {
            "selected variant ${variant.name} has no resource sources"
        }.static
        val appStaticResourceDirectoryPolicy = AppStaticResourceDirectoryPolicy(
            project.rootProject.projectDir.toPath(),
            project.projectDir.toPath(),
        )
        val appStaticResourceLayers = appStaticResourceSources.map { layers ->
            layers.map { layer ->
                layer.filter { directory ->
                    appStaticResourceDirectoryPolicy.accepts(directory.asFile.toPath())
                }
            }
        }
        val runtimeArtifacts = project.configurations
            .getByName("${variant.name}RuntimeClasspath")
            .incoming
            .artifactView {
                attributes.attribute(
                    ArtifactTypeDefinition.ARTIFACT_TYPE_ATTRIBUTE,
                    ANDROID_CLASSES_JAR,
                )
            }
            .artifacts
        val resolvedArtifacts = project.providers.provider {
            runtimeArtifacts.artifacts.sortedBy { artifact ->
                "${artifact.id.componentIdentifier.displayName}:${artifact.file.toPath().toAbsolutePath().normalize()}"
            }
        }
        val ownedProjectArtifacts = resolvedArtifacts.map { artifacts ->
            artifacts.filter { artifact -> artifact.ownedModulePath(resolvedOwnership.get().modulePaths) != null }
        }
        val hierarchyCompileClasspath = variant.compileClasspath
        val hierarchyRuntimeArtifacts = resolvedArtifacts.map { artifacts ->
            artifacts.filter { artifact -> artifact.ownedModulePath(resolvedOwnership.get().modulePaths) == null }
        }
        val hierarchyClasspath = project.files(
            hierarchyCompileClasspath,
            hierarchyRuntimeArtifacts.map { artifacts -> artifacts.map { artifact -> artifact.file } },
        )
        val codeMapping = project.tasks.register(
            "generateHardening${HardeningNames.taskSuffix(variant.name)}CodeMapping",
            GenerateHardeningCodeMappingTask::class.java,
        ) {
            group = "hardening"
            description = "Generates the stable pre-R8 code mapping for ${variant.name}."
            dependsOn(runtimeArtifacts.artifactFiles)
            dependsOn(appStaticResourceSources)
            variantName.set(variant.name)
            namespace.set(variant.namespace)
            applicationModulePath.set(project.path)
            unresolvedAppReflectionPolicy.set(extension.contracts.unresolvedAppReflection.map { it.name })
            externalNamesPolicy.set(extension.contracts.externalNames.map { it.name })
            repositoryRoot.set(project.rootProject.layout.projectDirectory)
            ownership.set(project.providers.provider { extension.ownership.resolve(project.rootProject) })
            appStaticResourceDirectories.set(appStaticResourceLayers.map { layers -> layers.flatten() })
            appStaticResourceLayerDirectoryCounts.set(appStaticResourceLayers.map { layers -> layers.map { it.size } })
            appStaticResourceLayerIdentity.set(resourceLayerIdentity(project, appStaticResourceLayers))
            appStaticResourceInputs.from(appStaticResourceInputs(project, appStaticResourceSources))
            preparedRegistry.set(tasks.prepare.flatMap { it.preparedDirectory.file("registry.json") })
            lineageSeed.set(tasks.prepare.flatMap { it.preparedDirectory.file("seed.bin") })
            preparedState.set(tasks.prepare.flatMap { it.preparedDirectory.file(PREPARED_STATE_FILE) })
            this.effectiveR8Rules.set(effectiveR8Rules)
            runtimeClasspath.from(hierarchyClasspath)
            bootClasspath.from(androidComponents.sdkComponents.bootClasspath)
            ownedArtifactMetadata.set(project.providers.provider {
                val projectArtifacts = ownedProjectArtifacts.get().associateBy { artifact ->
                    artifact.file.toPath().toAbsolutePath().normalize()
                }
                val inputs = projectClassJars.get().map { file -> file.asFile.toPath() } +
                    projectClassDirectories.get().map { directory -> directory.asFile.toPath() }
                inputs.map { input ->
                    val path = input.toAbsolutePath().normalize()
                    val artifact = projectArtifacts[path]
                    ClassArtifactInputCodec.encode(
                        if (artifact == null) {
                            ClassArtifactInput("project ${project.path}", project.path, path)
                        } else {
                            ClassArtifactInput(
                                artifact.id.componentIdentifier.displayName,
                                requireNotNull(artifact.ownedModulePath(resolvedOwnership.get().modulePaths)),
                                path,
                            )
                        },
                    )
                }.sorted()
            })
            hierarchyArtifactMetadata.set(project.providers.provider {
                val ownedPaths = (
                    projectClassJars.get().map { file -> file.asFile.toPath() } +
                        projectClassDirectories.get().map { directory -> directory.asFile.toPath() }
                    ).mapTo(linkedSetOf()) { path -> path.toAbsolutePath().normalize() }
                val bootPaths = bootClasspath.files
                    .mapTo(linkedSetOf()) { file -> file.toPath().toAbsolutePath().normalize() }
                val runtimePaths = hierarchyRuntimeArtifacts.get()
                    .mapTo(linkedSetOf()) { artifact -> artifact.file.toPath().toAbsolutePath().normalize() }
                val runtimePrecedence = bootPaths.size
                val compilePrecedence = runtimePrecedence + 1
                val hierarchy = hierarchyClasspath.files.mapNotNull { file ->
                    val path = file.toPath().toAbsolutePath().normalize()
                    if (path in ownedPaths || path in bootPaths) null else ClassArtifactInput(
                        "${variant.name} compile and runtime hierarchy",
                        modulePath = null,
                        path,
                        hierarchyPrecedence = if (path in runtimePaths) runtimePrecedence else compilePrecedence,
                    )
                }
                val boot = bootClasspath.files.map { file ->
                    ClassArtifactInput("Android boot classpath", modulePath = null, file.toPath())
                }
                (hierarchy + boot).map(ClassArtifactInputCodec::encode).sorted()
            })
            codeRegistry.set(
                project.layout.buildDirectory.file(
                    "intermediates/hardening/${variant.name}/code-naming/code-registry.json",
                ),
            )
            codeMapping.set(
                project.layout.buildDirectory.file(
                    "intermediates/hardening/${variant.name}/code-naming/code-mapping.txt",
                ),
            )
            applyMappingRules.set(
                project.layout.buildDirectory.file(
                    "intermediates/hardening/${variant.name}/code-naming/applymapping.pro",
                ),
            )
            codeNamingManifest.set(
                project.layout.buildDirectory.file(
                    "reports/hardening/${variant.name}/code-naming.json",
                ),
            )
            potentialBeanFieldsManifest.set(
                project.layout.buildDirectory.file(
                    "reports/hardening/${variant.name}/potential-bean-fields.json",
                ),
            )
        }
        tasks.audit.configure {
            dependsOn(appStaticResourceSources)
            appStaticResourceDirectories.set(appStaticResourceLayers.map { layers -> layers.flatten() })
            appStaticResourceLayerDirectoryCounts.set(appStaticResourceLayers.map { layers -> layers.map { it.size } })
            appStaticResourceLayerIdentity.set(resourceLayerIdentity(project, appStaticResourceLayers))
            appStaticResourceInputs.from(appStaticResourceInputs(project, appStaticResourceSources))
        }
        variant.artifacts.forScope(ScopedArtifacts.Scope.PROJECT)
            .use(codeMapping)
            .toGet(
                ScopedArtifact.CLASSES,
                GenerateHardeningCodeMappingTask::projectClassJars,
                GenerateHardeningCodeMappingTask::projectClassDirectories,
            )
        codeMapping.configure {
            projectClassJars.addAll(
                ownedProjectArtifacts.map { artifacts ->
                    artifacts.map { artifact ->
                        project.layout.file(project.providers.provider { artifact.file }).get()
                    }
                },
            )
        }
        variant.proguardFiles.add(codeMapping.flatMap(GenerateHardeningCodeMappingTask::applyMappingRules))
        requireNotNull(tasks.pipeline).rewrite.configure {
            codeRegistry.set(codeMapping.flatMap(GenerateHardeningCodeMappingTask::codeRegistry))
        }
        tasks.verify.configure {
            previousAppOnlyMapping.set(codeMapping.flatMap(GenerateHardeningCodeMappingTask::codeMapping))
            codeNamingManifest.set(codeMapping.flatMap(GenerateHardeningCodeMappingTask::codeNamingManifest))
            potentialBeanFieldsManifest.set(
                codeMapping.flatMap(GenerateHardeningCodeMappingTask::potentialBeanFieldsManifest),
            )
        }
        tasks.archive.configure {
            potentialBeanFieldsManifest.set(
                codeMapping.flatMap(GenerateHardeningCodeMappingTask::potentialBeanFieldsManifest),
            )
        }
    }

    private fun wireFilteredAppRules(
        project: Project,
        extension: AndroidHardeningExtension,
        variant: ApplicationVariant,
        tasks: HardeningVariantTasks,
    ): Provider<RegularFile> {
        val sourceRules = extension.rules.sourceFiles.files.sortedBy { it.toPath().toAbsolutePath().normalize().toString() }
        require(sourceRules.isNotEmpty()) { "androidHardening.rules.sourceFiles must not be empty" }
        sourceRules.forEach { file ->
            require(file.isFile && !Files.isSymbolicLink(file.toPath())) {
                "androidHardening.rules.sourceFiles contains a missing or unsafe file: $file"
            }
        }
        val suffix = HardeningNames.taskSuffix(variant.name)
        val generatedRules = project.tasks.register(
            "generateHardening${suffix}R8Rules",
            GenerateHardeningR8RulesTask::class.java,
        ) {
            group = "hardening"
            description = "Generates the filtered opt-in R8 rules for ${variant.name}."
            variantName.set(variant.name)
            sourceOccurrenceCount.set(sourceRules.size)
            this.sourceRules.from(extension.rules.sourceFiles)
            preserveExactRules.from(extension.rules.preserveExactRules)
            additionalRules.from(extension.rules.additionalRules)
            repositoryRoot.set(project.rootProject.layout.projectDirectory)
            ownership.set(project.providers.provider { extension.ownership.resolve(project.rootProject) })
            filteredRules.set(
                project.layout.buildDirectory.file(
                    "intermediates/hardening/${variant.name}/r8/filtered-proguard-rules.pro",
                ),
            )
            decisionManifest.set(
                project.layout.buildDirectory.file(
                    "reports/hardening/${variant.name}/r8-rules-manifest.json",
                ),
            )
        }
        variant.proguardFiles.add(generatedRules.flatMap(GenerateHardeningR8RulesTask::filteredRules))
        tasks.prepare.configure {
            dependsOn(generatedRules)
            hardeningRules.set(generatedRules.flatMap(GenerateHardeningR8RulesTask::filteredRules))
        }
        tasks.archive.configure {
            hardeningRules.set(generatedRules.flatMap(GenerateHardeningR8RulesTask::filteredRules))
        }
        tasks.audit.configure {
            dependsOn(generatedRules)
            r8RulesManifest.set(generatedRules.flatMap(GenerateHardeningR8RulesTask::decisionManifest))
        }
        return generatedRules.flatMap(GenerateHardeningR8RulesTask::filteredRules)
    }

    private fun replaceSelectedVariantSourceRules(
        android: ApplicationExtension,
        extension: AndroidHardeningExtension,
        requestedTasks: List<String>,
        projectPath: String,
    ) {
        val requestedVariants = extension.variants.included.get().filterTo(linkedSetOf()) { variant ->
            HardeningWiringGate.isHardeningTaskRequested(variant, requestedTasks, projectPath)
        }
        if (requestedVariants.isEmpty()) return

        val sourceRulePaths = extension.rules.sourceFiles.files.mapTo(linkedSetOf()) { file ->
            require(file.isFile && !Files.isSymbolicLink(file.toPath())) {
                "androidHardening.rules.sourceFiles contains a missing or unsafe file: $file"
            }
            file.toPath().toAbsolutePath().normalize()
        }
        require(sourceRulePaths.isNotEmpty()) { "androidHardening.rules.sourceFiles must not be empty" }

        val selectedVariants = resolveDslVariants(android, requestedVariants)
        val originalRules = selectedVariants
            .flatMap(DslVariant::dimensions)
            .distinctBy(System::identityHashCode)
            .associateWith { dimension -> dimension.proguardFiles.toList() }

        selectedVariants.forEach { selected ->
            val configuredPaths = selected.dimensions.flatMap { dimension ->
                originalRules.getValue(dimension).map { file -> file.toPath().toAbsolutePath().normalize() }
            }
            sourceRulePaths.forEach { sourceRule ->
                require(configuredPaths.count { configured -> configured == sourceRule } == 1) {
                    "androidHardening.rules.sourceFiles must identify an app ProGuard file exactly once " +
                        "for ${selected.name}: $sourceRule"
                }
            }
        }

        originalRules.forEach { (dimension, rules) ->
            dimension.setProguardFiles(
                rules.filterNot { file -> file.toPath().toAbsolutePath().normalize() in sourceRulePaths },
            )
        }
    }

    private fun resolveDslVariants(
        android: ApplicationExtension,
        requestedVariants: Set<String>,
    ): List<DslVariant> {
        val productFlavors = android.productFlavors.toList()
        val flavorsByDimension = if (
            productFlavors.isNotEmpty() && productFlavors.all { flavor -> flavor.dimension == null }
        ) {
            listOf(productFlavors)
        } else {
            android.flavorDimensions.map { dimension ->
                productFlavors.filter { flavor -> flavor.dimension == dimension }
            }
        }
        val flavorCombinations = flavorsByDimension.fold(listOf(emptyList<ProductFlavor>())) { combinations, flavors ->
            combinations.flatMap { combination -> flavors.map { flavor -> combination + flavor } }
        }
        val availableVariants = android.buildTypes.flatMap { buildType ->
            flavorCombinations.map { flavors ->
                DslVariant(
                    dslVariantName(flavors, buildType),
                    listOf(android.defaultConfig) + flavors + buildType,
                )
            }
        }
        val selected = availableVariants.filter { variant -> variant.name in requestedVariants }
        val missing = requestedVariants - selected.mapTo(linkedSetOf(), DslVariant::name)
        require(missing.isEmpty()) {
            "androidHardening variants cannot be resolved from the finalized Android DSL: $missing"
        }
        return selected
    }

    private fun dslVariantName(flavors: List<ProductFlavor>, buildType: BuildType): String = buildString {
        flavors.forEachIndexed { index, flavor ->
            append(if (index == 0) flavor.name else flavor.name.replaceFirstChar(Char::uppercaseChar))
        }
        if (isEmpty()) append(buildType.name) else append(buildType.name.replaceFirstChar(Char::uppercaseChar))
    }

    private data class DslVariant(
        val name: String,
        val dimensions: List<VariantDimension>,
    )

    private fun resourceLayerIdentity(
        project: Project,
        layers: Provider<List<List<Directory>>>,
    ): Provider<List<String>> {
        val root = project.rootProject.projectDir.toPath().toAbsolutePath().normalize()
        return layers.map { groupedDirectories ->
            groupedDirectories.mapIndexed { layer, directories ->
                "$layer:" + directories.joinToString("|") { directory ->
                    portable(root.relativize(directory.asFile.toPath().toAbsolutePath().normalize()))
                }
            }
        }
    }

    private fun appStaticResourceInputs(
        project: Project,
        sources: Provider<List<Collection<Directory>>>,
    ): FileCollection {
        val root = project.rootProject.projectDir.toPath().toAbsolutePath().normalize()
        val app = project.projectDir.toPath().toAbsolutePath().normalize()
        val policy = AppStaticResourceDirectoryPolicy(root, app)
        return project.files(sources).filter { file ->
            policy.accepts(file.toPath())
        }
    }

    private fun portable(path: Path): String = path.toString().replace('\\', '/')

    private fun identityProviders(project: Project, variant: ApplicationVariant): AndroidVariantIdentityProviders {
        val outputs = variant.outputs.toList()
        require(outputs.isNotEmpty()) { "selected Android variant ${variant.name} has no outputs" }
        val versionCode = project.providers.provider {
            val enabledOutputs = outputs.filter { it.enabled.get() }
            val selectedOutputs = enabledOutputs.ifEmpty { outputs }
            val values = selectedOutputs.map { it.versionCode.get() }.distinct()
            require(values.size == 1) {
                "selected Android variant ${variant.name} must have one effective versionCode, found $values"
            }
            values.single()
        }
        val versionName = project.providers.provider {
            val enabledOutputs = outputs.filter { it.enabled.get() }
            val selectedOutputs = enabledOutputs.ifEmpty { outputs }
            val values = selectedOutputs.map { output ->
                output.versionName.orNull?.takeIf(String::isNotBlank)
                    ?: throw IllegalArgumentException(
                        "selected Android variant ${variant.name} must have a nonblank versionName",
                    )
            }.distinct()
            require(values.size == 1) {
                "selected Android variant ${variant.name} must have one effective versionName, found $values"
            }
            values.single()
        }
        return AndroidVariantIdentityProviders(
            namespace = variant.namespace,
            applicationId = variant.applicationId,
            versionCode = versionCode,
            versionName = versionName,
        )
    }

    private class SigningDslSnapshot(
        private val defaultConfig: CapturedSigningMaterial?,
        private val buildTypes: Map<String, CapturedSigningMaterial?>,
        private val productFlavors: Map<String, CapturedSigningMaterial?>,
    ) {
        fun resolve(variant: ApplicationVariant): SigningMaterial {
            buildTypes[variant.buildType]?.let { return it.material() }
            val flavors = variant.productFlavors
                .mapNotNull { (_, flavor) -> productFlavors[flavor] }
                .distinctBy(CapturedSigningMaterial::configName)
            require(flavors.size <= 1) {
                "selected hardening variant has ambiguous flavor signing configurations"
            }
            return flavors.singleOrNull()?.material()
                ?: defaultConfig?.material()
                ?: throw IllegalArgumentException("selected hardening signing configuration is incomplete")
        }

        companion object {
            fun capture(android: ApplicationExtension): SigningDslSnapshot = SigningDslSnapshot(
                defaultConfig = CapturedSigningMaterial.capture(android.defaultConfig.signingConfig),
                buildTypes = android.buildTypes.associate { buildType ->
                    buildType.name to CapturedSigningMaterial.capture(buildType.signingConfig)
                },
                productFlavors = android.productFlavors.associate { flavor ->
                    flavor.name to CapturedSigningMaterial.capture(flavor.signingConfig)
                },
            )
        }
    }

    private fun ResolvedArtifactResult.ownedModulePath(ownedModules: Set<String>): String? =
        (id.componentIdentifier as? ProjectComponentIdentifier)
            ?.projectPath
            ?.takeIf(ownedModules::contains)

    private const val ANDROID_CLASSES_JAR = "android-classes-jar"

    private class CapturedSigningMaterial private constructor(
        val configName: String,
        private val storeFile: java.io.File?,
        private val storePassword: String?,
        private val keyAlias: String?,
        private val keyPassword: String?,
        private val storeType: String?,
    ) {
        fun material(): SigningMaterial = SigningMaterial.create(
            configName = configName,
            storeFile = storeFile?.toPath(),
            storePassword = storePassword,
            keyAlias = keyAlias,
            keyPassword = keyPassword,
            storeType = storeType,
        )

        override fun toString(): String = "CapturedSigningMaterial([redacted])"

        companion object {
            fun capture(config: ApkSigningConfig?): CapturedSigningMaterial? = config?.let {
                CapturedSigningMaterial(
                    configName = it.name,
                    storeFile = it.storeFile,
                    storePassword = it.storePassword,
                    keyAlias = it.keyAlias,
                    keyPassword = it.keyPassword,
                    storeType = it.storeType,
                )
            }
        }
    }
}
