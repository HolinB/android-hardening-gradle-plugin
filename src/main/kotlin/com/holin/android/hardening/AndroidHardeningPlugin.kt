package com.holin.android.hardening

import com.android.build.api.variant.ApplicationAndroidComponentsExtension
import com.android.build.api.dsl.ApplicationExtension
import com.holin.android.hardening.audit.LegacyPluginObservationCodec
import com.holin.android.hardening.audit.LegacyPluginProbe
import com.holin.android.hardening.audit.LegacyPluginBaselineVerifier
import com.holin.android.hardening.audit.LegacyPluginDeclarationCodec
import com.holin.android.hardening.audit.RuntimeArtifactInputCodec
import com.holin.android.hardening.state.FixedSeedDerivation
import com.holin.android.hardening.state.HardeningStateLockService
import com.holin.android.hardening.state.InvocationSaltService
import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.PortableStateMigrationDescriptorLoader
import com.holin.android.hardening.tasks.ArchiveHardeningTask
import com.holin.android.hardening.tasks.AssembleHardeningUniversalApkTask
import com.holin.android.hardening.tasks.AssembleOrdinaryUniversalApkTask
import com.holin.android.hardening.tasks.BUNDLETOOL_WORKER_RUNTIME_COORDINATES
import com.holin.android.hardening.tasks.BundletoolBuildApksWorkAction
import com.holin.android.hardening.tasks.AuditHardeningTask
import com.holin.android.hardening.tasks.BenchmarkHardeningTask
import com.holin.android.hardening.tasks.HardeningEntryTask
import com.holin.android.hardening.tasks.CaptureHardeningBaselineTask
import com.holin.android.hardening.tasks.CompareHardeningSimilarityTask
import com.holin.android.hardening.tasks.CompareExternalHardeningAabTask
import com.holin.android.hardening.tasks.SmokeHardeningTask
import com.holin.android.hardening.tasks.PrepareHardeningTask
import com.holin.android.hardening.tasks.PREPARED_STATE_FILE
import com.holin.android.hardening.tasks.RewriteHardeningBundleTask
import com.holin.android.hardening.tasks.SignHardeningBundleTask
import com.holin.android.hardening.tasks.ValidateHardeningBundleTask
import com.holin.android.hardening.tasks.VerifyHardeningTask
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import org.gradle.api.Action
import org.gradle.api.GradleException
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.Task
import org.gradle.api.artifacts.type.ArtifactTypeDefinition
import org.gradle.api.artifacts.ExternalModuleDependency
import org.gradle.api.file.RegularFile
import org.gradle.api.execution.TaskExecutionGraph
import org.gradle.api.provider.Provider
import org.gradle.api.services.BuildService
import org.gradle.api.services.BuildServiceParameters
import org.gradle.api.tasks.TaskProvider

internal data class HardeningBundlePipelineRequest(
    val project: Project,
    val extension: AndroidHardeningExtension,
    val context: AgpVariantContext,
    val configurationSha256: Provider<String>,
    val saltService: Provider<InvocationSaltService>,
    val lockService: Provider<HardeningStateLockService>,
    val tasks: HardeningVariantTasks,
)

internal class HardeningPluginRegistration {
    internal lateinit var extension: AndroidHardeningExtension
        private set

    private val registeredVariants = linkedSetOf<String>()
    private var androidApplicationApplied = false

    fun configure(project: Project) {
        extension = project.extensions.create(
            "androidHardening",
            AndroidHardeningExtension::class.java,
            project.objects,
            project.layout,
        )
        project.gradle.taskGraph.whenReady(object : Action<TaskExecutionGraph> {
            override fun execute(graph: TaskExecutionGraph) {
                val graphTasks = graph.allTasks
                if (graphTasks.any { task -> task.project == project && task.group == HARDENING_GROUP }) {
                    val forbidden = HardeningWiringGate.forbiddenTaskNames(graphTasks.map { task -> task.path })
                    if (forbidden.isNotEmpty()) {
                        throw GradleException(
                            "forbidden task graph contamination in Android hardening: ${forbidden.joinToString()}",
                        )
                    }
                }
            }
        })
        project.afterEvaluate {
            if (!androidApplicationApplied) {
                extension.variants.included.get().forEach { variant ->
                    val resolved = project.provider { AndroidVariantIdentityResolver.resolve(project, variant) }
                    val identity = AndroidVariantIdentityProviders(
                        namespace = resolved.map(AndroidVariantIdentity::namespace),
                        applicationId = resolved.map(AndroidVariantIdentity::applicationId),
                        versionCode = resolved.map(AndroidVariantIdentity::versionCode),
                        versionName = resolved.map(AndroidVariantIdentity::versionName),
                    )
                    registerVariantTasks(
                        project,
                        AgpVariantContext(
                            variant,
                            identity,
                            null,
                            false,
                            null,
                        ),
                        null,
                    )
                }
            }
        }
        project.gradle.projectsEvaluated {
            if (androidApplicationApplied) {
                val missing = extension.variants.included.get() - registeredVariants
                require(missing.isEmpty()) { "selected Android hardening variants do not exist: ${missing.sorted()}" }
            }
        }
    }

    fun markAndroidApplicationApplied() {
        androidApplicationApplied = true
    }

    fun registerVariantTasks(
        project: Project,
        context: AgpVariantContext,
        pipelineWiring: ((HardeningBundlePipelineRequest) -> HardeningBundlePipelineTasks)?,
    ): HardeningVariantTasks {
        val variant = context.variantName
        check(registeredVariants.add(variant)) { "hardening tasks were registered twice for $variant" }
        val variantIdentity = context.identity
        val resolvedOwnership = project.providers.provider { extension.resolveOwnership(project.rootProject) }
        val declaredLegacyPlugins = project.providers.provider {
            extension.legacyPlugins.resolve(project.rootProject)
        }
        val completeConfigurationSha256 = context.bundle?.let { bundleContext ->
            project.providers.provider {
                OwnedSimilarityConfigurationIdentity.sha256(
                    extension,
                    variant,
                    variantIdentity.namespace.get(),
                    variantIdentity.applicationId.get(),
                    variantIdentity.versionCode.get(),
                    variantIdentity.versionName.get(),
                    bundleContext.signingMaterial.certificateSha256(),
                    resolvedOwnership.get(),
                    declaredLegacyPlugins.get(),
                    Sha256.file(extension.legacyPlugins.baselineFile.get().asFile.toPath()),
                )
            }
        }
        val suffix = HardeningNames.taskSuffix(variant)
        val bundleCommand = "./gradlew -PandroidHardening=true hardeningBundle$suffix"
        val assembleCommand = "./gradlew -PandroidHardening=true hardeningAssemble$suffix"
        val saltService = project.gradle.sharedServices.registerIfAbsent(
            "androidHardeningInvocationSalt${project.path.replace(':', '_')}$suffix",
            InvocationSaltService::class.java,
        ) {
            parameters.fixedSeedSha256.set(
                extension.reproducibility.fixedSeed.map(FixedSeedDerivation::seedSha256),
            )
        }
        val lockService = project.gradle.sharedServices.registerIfAbsent(
            "androidHardeningStateLock${project.path.replace(':', '_')}$suffix",
            HardeningStateLockService::class.java,
        ) {
            parameters.lockFile.set(
                extension.mapping.storeDirectory.file(
                    extension.projectKey.map { projectKey -> "$projectKey/$variant/locks/state.lock" },
                ),
            )
            parameters.projectPath.set(project.path)
            parameters.variant.set(variant)
            parameters.timeoutSeconds.set(extension.mapping.lockTimeoutSeconds)
            parameters.stateBoundary.set(project.rootProject.layout.projectDirectory)
        }
        val prepare = project.tasks.register("prepareHardening$suffix", PrepareHardeningTask::class.java) {
            group = HARDENING_GROUP
            description = "Prepares immutable hardening state for $variant."
            projectKey.set(extension.projectKey)
            variantName.set(variant)
            namespace.set(variantIdentity.namespace)
            applicationId.set(variantIdentity.applicationId)
            configurationSchema.set(configurationSchema(variant))
            completeConfigurationSha256?.let { configurationSha256 ->
                reproducibilityConfigurationSha256.set(
                    extension.reproducibility.fixedSeed.flatMap { configurationSha256 },
                )
            }
            reusePrevious.set(extension.mapping.reusePrevious)
            keepHistory.set(extension.mapping.keepHistory)
            quarantineInvalid.set(extension.mapping.quarantineInvalid)
            autoMigrateLegacyState.set(extension.compatibility.autoMigrateLegacyState)
            migrationDescriptor.set(extension.compatibility.migrationDescriptor)
            mappingStoreDirectory.set(extension.mapping.storeDirectory)
            repositoryRoot.set(project.rootProject.layout.projectDirectory)
            ownership.set(resolvedOwnership)
            preparedDirectory.set(
                project.layout.buildDirectory.dir(
                    saltService.map { service -> "hardening/$variant/prepared-${service.invocationIdSha256()}" },
                ),
            )
            appOnlyPreviousMapping.set(preparedDirectory.file("app-only-previous-mapping.txt"))
            applyMappingRules.set(preparedDirectory.file("applymapping.pro"))
            this.lockService.set(lockService)
            this.saltService.set(saltService)
            usesService(lockService)
            usesService(saltService)
            configureInternalGuard(extension, bundleCommand)
            doFirst { extension.validateFor(project, variant) }
        }
        val audit = lifecycleTask(project, "auditHardening$suffix", AuditHardeningTask::class.java, extension, prepare, bundleCommand)
        audit.configure {
            fullAuditEnabled.set(false)
            variantName.set(variant)
            namespace.set(variantIdentity.namespace)
            unresolvedAppReflectionPolicy.set(extension.contracts.unresolvedAppReflection.map { it.name })
            unresolvedResourceLookupPolicy.set(extension.contracts.unresolvedResourceLookup.map { it.name })
            externalNamesPolicy.set(extension.contracts.externalNames.map { it.name })
            repositoryRoot.set(project.rootProject.layout.projectDirectory)
            appDirectory.set(project.layout.projectDirectory)
            ownership.set(resolvedOwnership)
            runtimeArtifactMetadata.convention(emptyList())
            legacyPluginsBaseline.set(extension.legacyPlugins.baselineFile)
            legacyPluginDeclarations.set(
                declaredLegacyPlugins.map { declarations -> declarations.map(LegacyPluginDeclarationCodec::encode) },
            )
            legacyPluginConfigurationInputs.from(
                declaredLegacyPlugins.map { declarations ->
                    declarations.flatMap(LegacyPluginDeclaration::configurationInputs)
                        .distinct()
                        .sorted()
                        .map(project.rootProject::file)
                },
            )
            legacyPluginObservations.convention(emptyList())
            auditReport.set(
                project.layout.buildDirectory.file(
                    "reports/hardening/$variant/audit.json",
                ),
            )
        }
        val verify = lifecycleTask(project, "verifyHardening$suffix", VerifyHardeningTask::class.java, extension, audit, bundleCommand)
        verify.configure {
            variantName.set(variant)
            namespace.set(variantIdentity.namespace)
            repositoryRoot.set(project.rootProject.layout.projectDirectory)
            ownership.set(resolvedOwnership)
            artifactBoundary.set(project.layout.buildDirectory)
            preparedState.set(prepare.flatMap { task -> task.preparedDirectory.file(PREPARED_STATE_FILE) })
            previousAppOnlyMapping.set(prepare.flatMap(PrepareHardeningTask::appOnlyPreviousMapping))
            mappingVerificationReport.set(
                project.layout.buildDirectory.file(
                    "reports/hardening/$variant/mapping-verification.json",
                ),
            )
        }
        val archive = project.tasks.register("archiveHardening$suffix", ArchiveHardeningTask::class.java) {
            group = HARDENING_GROUP
            description = "Atomically archives verified hardening state for $variant."
            dependsOn(verify)
            projectKey.set(extension.projectKey)
            versionCode.set(variantIdentity.versionCode)
            variantName.set(variant)
            namespace.set(variantIdentity.namespace)
            applicationId.set(variantIdentity.applicationId)
            configurationSchema.set(configurationSchema(variant))
            mappingStoreDirectory.set(extension.mapping.storeDirectory)
            ownership.set(resolvedOwnership)
            preparedDirectory.set(prepare.flatMap(PrepareHardeningTask::preparedDirectory))
            artifactBoundary.set(project.layout.buildDirectory)
            publishedBundle.set(
                project.layout.buildDirectory.file(
                    "outputs/hardening/$variant/${variant}-hardened.aab",
                ),
            )
            publishedReport.set(
                project.layout.buildDirectory.file(
                    "reports/hardening/$variant/bundle-verification.json",
                ),
            )
            publishedMappingVerificationReport.set(
                project.layout.buildDirectory.file(
                    "reports/hardening/$variant/mapping-verification.json",
                ),
            )
            auditReport.set(audit.flatMap(AuditHardeningTask::auditReport))
            this.lockService.set(lockService)
            this.saltService.set(saltService)
            usesService(lockService)
            usesService(saltService)
            configureInternalGuard(extension, bundleCommand)
        }
        val bundle = project.tasks.register("hardeningBundle$suffix", HardeningEntryTask::class.java) {
            configureEntry(extension, archive, bundleCommand)
        }
        val assemble = project.tasks.register("hardeningAssemble$suffix", HardeningEntryTask::class.java) {
            configureEntry(extension, archive, assembleCommand)
        }
        val benchmark = lifecycleTask(
            project,
            "benchmarkHardening$suffix",
            BenchmarkHardeningTask::class.java,
            extension,
            archive,
            bundleCommand,
        )
        project.tasks.register(
            "compareExternalHardening$suffix",
            CompareExternalHardeningAabTask::class.java,
        ) {
            group = HARDENING_GROUP
            description = "Compares the verified $variant hardened AAB with a caller-supplied external AAB."
            dependsOn(
                project.providers.gradleProperty(REFERENCE_AAB_PROPERTY)
                    .map { listOf(archive) }
                    .orElse(emptyList()),
            )
            referenceAab.set(
                project.layout.file(
                    project.providers.gradleProperty(REFERENCE_AAB_PROPERTY)
                        .map { path -> project.rootProject.file(path) },
                ),
            )
            candidateAab.set(archive.flatMap(ArchiveHardeningTask::publishedBundle))
            jsonReport.set(
                project.layout.buildDirectory.file(
                    "reports/hardening/$variant/external-aab-similarity-report.json",
                ),
            )
            markdownReport.set(
                project.layout.buildDirectory.file(
                    "reports/hardening/$variant/external-aab-similarity-report.md",
                ),
            )
            artifactBoundary.set(project.layout.buildDirectory)
            configureInternalGuard(
                extension,
                "./gradlew -PandroidHardening=true " +
                    "-P$REFERENCE_AAB_PROPERTY=/absolute/path/reference.aab compareExternalHardening$suffix",
            )
            doFirst { extension.validateFor(project, variant) }
        }
        val captureBaseline: TaskProvider<CaptureHardeningBaselineTask>?
        val compare: TaskProvider<CompareHardeningSimilarityTask>?
        val smoke: TaskProvider<SmokeHardeningTask>?
        val run: TaskProvider<HardeningEntryTask>?
        if (variant in extension.variants.included.get()) {
            val baselineRoot = extension.similarity.baselineDirectory.dir(
                extension.projectKey.map { projectKey -> "$projectKey/$variant/v1" },
            )
            captureBaseline = project.tasks.register(
                "captureHardeningBaseline$suffix",
                CaptureHardeningBaselineTask::class.java,
            ) {
                group = HARDENING_GROUP
                description = "Captures the immutable owned-artifact similarity baseline for $variant."
                projectKey.set(extension.projectKey)
                variantName.set(variant)
                baselineDirectory.set(extension.similarity.baselineDirectory)
                this.baselineRoot.set(baselineRoot)
                repositoryRoot.set(project.rootProject.layout.projectDirectory)
                artifactBoundary.set(project.layout.buildDirectory)
                configureInternalGuard(extension, "./gradlew -PandroidHardening=true captureHardeningBaseline$suffix")
                doFirst { extension.validateFor(project, variant) }
            }
            compare = project.tasks.register(
                "compareHardening$suffix",
                CompareHardeningSimilarityTask::class.java,
            ) {
                group = HARDENING_GROUP
                description = "Compares $variant against its immutable owned-artifact baseline."
                projectKey.set(extension.projectKey)
                variantName.set(variant)
                minimumImprovementPoints.set(extension.similarity.minimumImprovementPoints)
                autoMigrateLegacyState.set(extension.compatibility.autoMigrateLegacyState)
                migrationDescriptor.set(extension.compatibility.migrationDescriptor)
                baselineDirectory.set(extension.similarity.baselineDirectory)
                this.baselineRoot.set(baselineRoot)
                repositoryRoot.set(project.rootProject.layout.projectDirectory)
                artifactBoundary.set(project.layout.buildDirectory)
                this.lockService.set(lockService)
                usesService(lockService)
                jsonReport.set(project.layout.buildDirectory.file("reports/hardening/$variant/similarity-report.json"))
                markdownReport.set(project.layout.buildDirectory.file("reports/hardening/$variant/similarity-report.md"))
                configureInternalGuard(extension, "./gradlew -PandroidHardening=true compareHardening$suffix")
                doFirst { extension.validateFor(project, variant) }
            }
            smoke = project.tasks.register("smokeHardening$suffix", SmokeHardeningTask::class.java) {
                group = HARDENING_GROUP
                description = "Runs device acceptance for the relatively accepted $variant hardened APK."
                deviceExecutionAuthorized.set(project.providers.provider {
                    HardeningWiringGate.isHardeningRunRequested(
                        variant,
                        project.gradle.startParameter.taskNames,
                        project.path,
                    )
                })
                serial.set(extension.deviceAcceptance.serial)
                autoSelectSingleDevice.set(extension.deviceAcceptance.autoSelectSingleDevice)
                applicationId.set(extension.deviceAcceptance.applicationId)
                applicationIdFromVariant.set(extension.deviceAcceptance.applicationIdFromVariant)
                variantApplicationId.set(variantIdentity.applicationId)
                launchActivity.set(extension.deviceAcceptance.launchActivity)
                launchActivityFromManifest.set(extension.deviceAcceptance.launchActivityFromManifest)
                context.mergedManifest?.let(mergedManifest::set)
                stabilitySeconds.set(extension.deviceAcceptance.stabilitySeconds)
                runTaskName.set("hardeningRun$suffix")
                comparisonReport.set(
                    project.layout.buildDirectory.file("reports/hardening/$variant/similarity-report.json"),
                )
                artifactBoundary.set(project.layout.buildDirectory)
                configureInternalGuard(extension, "./gradlew -PandroidHardening=true smokeHardening$suffix")
                doFirst { extension.validateFor(project, variant) }
            }
            smoke.configure {
                mustRunAfter(compare)
                dependsOn(deviceExecutionAuthorized.map { authorized ->
                    if (authorized) listOf(compare) else emptyList()
                })
            }
            archive.configure {
                dependsOn(project.providers.provider {
                    if (
                        HardeningWiringGate.isHardeningRunRequested(
                            variant,
                            project.gradle.startParameter.taskNames,
                            project.path,
                        )
                    ) {
                        listOf(smoke)
                    } else {
                        emptyList()
                    }
                })
            }
            run = project.tasks.register("hardeningRun$suffix", HardeningEntryTask::class.java) {
                dependsOn(compare)
                dependsOn(archive)
                configureEntry(
                    extension,
                    smoke,
                    "./gradlew -PandroidHardening=true hardeningRun$suffix",
                )
            }
        } else {
            captureBaseline = null
            compare = null
            smoke = null
            run = null
        }
        val tasks = HardeningVariantTasks(
            prepare, audit, verify, archive, bundle, assemble, benchmark,
            captureBaseline, compare, smoke, run, pipeline = null,
        )
        val pipeline = context.bundle?.let {
            requireNotNull(pipelineWiring)(
                HardeningBundlePipelineRequest(
                    project,
                    extension,
                    context,
                    requireNotNull(completeConfigurationSha256),
                    saltService,
                    lockService,
                    tasks,
                ),
            )
        }
        return tasks.copy(pipeline = pipeline)
    }

    private fun <T : Task> lifecycleTask(
        project: Project,
        name: String,
        type: Class<T>,
        extension: AndroidHardeningExtension,
        dependency: TaskProvider<out Task>,
        correctedCommand: String,
    ): TaskProvider<T> = project.tasks.register(name, type) {
        group = HARDENING_GROUP
        dependsOn(dependency)
        configureInternalGuard(extension, correctedCommand)
    }

    private fun Task.configureInternalGuard(extension: AndroidHardeningExtension, correctedCommand: String) {
        onlyIf("androidHardening is enabled or this task was directly requested") {
            if (extension.enabled.get()) {
                true
            } else if (project.gradle.startParameter.taskNames.any { requested -> requested.substringAfterLast(':') == name }) {
                throw GradleException("Android hardening is disabled. Run exactly:\n$correctedCommand")
            } else {
                false
            }
        }
    }

    private fun HardeningEntryTask.configureEntry(
        extension: AndroidHardeningExtension,
        dependency: TaskProvider<out Task>,
        command: String,
    ) {
        group = HARDENING_GROUP
        dependsOn(dependency)
        hardeningEnabled.set(extension.enabled)
        correctedCommand.set(command)
    }

    private fun AndroidHardeningExtension.validateFor(project: Project, variant: String) {
        validateV1()
        resolveOwnership(project.rootProject)
        val root = project.rootProject.projectDir.toPath().toAbsolutePath().normalize()
        val baseline = legacyPlugins.baselineFile.orNull?.asFile?.toPath()?.toAbsolutePath()?.normalize()
            ?: throw IllegalArgumentException("legacyPlugins.baselineFile must be configured for hardening")
        require(baseline.startsWith(root) && baseline != root) {
            "legacyPlugins.baselineFile escapes the repository boundary"
        }
        require(Files.isRegularFile(baseline, NOFOLLOW_LINKS) && !Files.isSymbolicLink(baseline)) {
            "legacyPlugins.baselineFile is missing or is not a non-symlink regular file: $baseline"
        }
        if (legacyPlugins.verifyCompatibility.get()) {
            require(!legacyPlugins.plugins.isEmpty()) {
                "legacyPlugins must declare at least one plugin when compatibility verification is enabled"
            }
        }
        legacyPlugins.resolve(project.rootProject)
        if (compatibility.autoMigrateLegacyState.get()) {
            val descriptor = compatibility.migrationDescriptor.orNull?.asFile?.toPath()
                ?: throw IllegalArgumentException(
                    "compatibility.migrationDescriptor must be configured when automatic migration is enabled",
                )
            PortableStateMigrationDescriptorLoader.load(
                root,
                descriptor,
                projectKey.get(),
                variant,
            )
        }
    }

    private fun AndroidHardeningExtension.resolveOwnership(rootProject: Project): HardeningOwnership =
        if (androidApplicationApplied) ownership.resolve(rootProject) else ownership.resolvePortable(rootProject)

    private companion object {
        const val HARDENING_GROUP = "hardening"
        const val REFERENCE_AAB_PROPERTY = "androidHardeningReferenceAab"
    }
}

internal class AgpHardeningAdapter {
    fun configure(project: Project, registration: HardeningPluginRegistration) {
        registration.markAndroidApplicationApplied()
        AgpHardeningConfigurer.configure(project, registration.extension) { context ->
            registration.registerVariantTasks(project, context, ::wireBundlePipeline)
        }
    }

    private fun wireBundlePipeline(
        request: HardeningBundlePipelineRequest,
    ): HardeningBundlePipelineTasks {
        val project = request.project
        val extension = request.extension
        val variant = request.context.variantName
        val variantIdentity = request.context.identity
        val bundleCommand = "./gradlew -PandroidHardening=true hardeningBundle${HardeningNames.taskSuffix(variant)}"
        val assembleCommand = "./gradlew -PandroidHardening=true hardeningAssemble${HardeningNames.taskSuffix(variant)}"
        val bundleContext = requireNotNull(request.context.bundle)
        val configurationSha256 = request.configurationSha256
        val saltService = request.saltService
        val lockService = request.lockService
        val tasks = request.tasks
        val suffix = HardeningNames.taskSuffix(variant)
        val resolvedOwnership = project.providers.provider { extension.ownership.resolve(project.rootProject) }
        val androidComponents = project.extensions.getByType(ApplicationAndroidComponentsExtension::class.java)
        val androidDsl = project.extensions.getByType(ApplicationExtension::class.java)
        val buildToolsVersion = project.providers.provider { androidDsl.buildToolsVersion }
        val aapt2Executable = Aapt2ExecutableResolver.resolve(
            androidComponents.sdkComponents,
            androidComponents.sdkComponents.sdkDirectory,
            buildToolsVersion,
        )
        val zipalignExecutable = androidComponents.sdkComponents.sdkDirectory.zip(buildToolsVersion) { sdk, version ->
            sdk.file("build-tools/$version/${zipalignExecutableName()}")
        }
        val bundletoolWorkerRuntime = project.configurations.findByName(BUNDLETOOL_WORKER_CONFIGURATION)
            ?: project.configurations.create(BUNDLETOOL_WORKER_CONFIGURATION) {
                isCanBeConsumed = false
                isCanBeResolved = true
                isVisible = false
                description = "Version-locked runtime for the process-isolated hardening bundletool worker."
                BUNDLETOOL_WORKER_RUNTIME_COORDINATES.forEach { coordinate ->
                    val dependency = project.dependencies.create(coordinate)
                    require(dependency is ExternalModuleDependency) { "bundletool worker dependency must be external" }
                    dependency.isTransitive = false
                    project.dependencies.add(name, dependency)
                }
            }
        val bundletoolWorkerImplementation = project.files(
            java.io.File(BundletoolBuildApksWorkAction::class.java.protectionDomain.codeSource.location.toURI()),
        )
        val invocationDirectory = saltService.map { service ->
            "hardening/$variant/invocations/${service.invocationIdSha256()}"
        }
        val runtimeArtifacts = project.configurations
            .getByName("${variant}RuntimeClasspath")
            .incoming
            .artifactView {
                attributes.attribute(
                    ArtifactTypeDefinition.ARTIFACT_TYPE_ATTRIBUTE,
                    ArtifactTypeDefinition.JAR_TYPE,
                )
            }
            .artifacts
        tasks.audit.configure {
            fullAuditEnabled.set(true)
            runtimeClasspath.from(runtimeArtifacts.artifactFiles)
            runtimeArtifactMetadata.set(
                project.providers.provider {
                    runtimeArtifacts.artifacts.map { artifact ->
                        RuntimeArtifactInputCodec.encode(
                            artifact.id.componentIdentifier.displayName,
                            artifact.file.toPath(),
                        )
                    }.sorted()
                },
            )
        }
        project.gradle.projectsEvaluated {
            val declarations = extension.legacyPlugins.resolve(project.rootProject)
            val baselineFile = extension.legacyPlugins.baselineFile.orNull?.asFile?.toPath()
                ?: throw IllegalArgumentException("legacy plugin baseline is required for a full hardening audit")
            val probeExpectations = LegacyPluginBaselineVerifier.probeExpectations(
                baselineFile,
                project.rootProject.projectDir.toPath(),
                declarations,
            )
            val observations = LegacyPluginProbe.observe(project, probeExpectations)
                .map(LegacyPluginObservationCodec::encode)
            tasks.audit.configure { legacyPluginObservations.set(observations) }
        }
        val unsigned = project.tasks.register(
            "rewriteHardening${suffix}Bundle",
            RewriteHardeningBundleTask::class.java,
        ) {
            group = HARDENING_GROUP
            description = "Creates an unsigned hardened copy of the $variant AAB."
            dependsOn(tasks.audit)
            inputBundle.set(bundleContext.ordinaryBundle)
            r8Mapping.set(bundleContext.obfuscationMapping)
            this.namespace.set(variantIdentity.namespace)
            applicationId.set(variantIdentity.applicationId)
            minimumCodeCoverage.set(extension.code.diversification.minimumCoverage)
            minimumCodeSimHashDistance.set(extension.code.diversification.minimumSimHashDistance)
            maximumDexGrowth.set(extension.code.diversification.maximumGrowth)
            enforceMaximumDexGrowth.set(extension.code.diversification.enforceMaximumGrowth)
            minimumImageCoverage.set(extension.resources.bitmapDiversification.minimumCoverage)
            minimumImageSsim.set(extension.resources.bitmapDiversification.minimumSsim)
            minimumImagePHashDistance.set(extension.resources.bitmapDiversification.minimumPHashDistance)
            artifactBoundary.set(project.layout.buildDirectory)
            repositoryRoot.set(project.rootProject.layout.projectDirectory)
            ownership.set(resolvedOwnership)
            applicationModulePath.set(project.path)
            preparedDirectory.set(tasks.prepare.flatMap(PrepareHardeningTask::preparedDirectory))
            unsignedBundle.set(
                project.layout.buildDirectory.file(
                    invocationDirectory.map { directory -> "$directory/unsigned.aab" },
                ),
            )
            rewriteManifest.set(
                project.layout.buildDirectory.file(
                    invocationDirectory.map { directory -> "$directory/rewrite-manifest.json" },
                ),
            )
            semanticResults.set(
                project.layout.buildDirectory.file(
                    invocationDirectory.map { directory -> "$directory/semantic-results.json" },
                ),
            )
            planReport.set(
                project.layout.buildDirectory.file(
                    invocationDirectory.map { directory -> "$directory/transformation-report.json" },
                ),
            )
            ownedArtifactInventory.set(
                project.layout.buildDirectory.file(
                    invocationDirectory.map { directory -> "$directory/owned-artifact-inventory.json" },
                ),
            )
            ownedArtifactAnalysisInventory.set(
                project.layout.buildDirectory.file(
                    invocationDirectory.map { directory -> "$directory/owned-artifact-analysis-inventory.json" },
                ),
            )
            this.saltService.set(saltService)
            usesService(saltService)
            configureInternalGuard(extension, bundleCommand)
        }
        val material = bundleContext.signingMaterial
        val signed = project.tasks.register(
            "signHardening${suffix}Bundle",
            SignHardeningBundleTask::class.java,
        ) {
            group = HARDENING_GROUP
            description = "Signs the hardened $variant AAB candidate with the variant signing configuration."
            dependsOn(unsigned)
            unsignedBundle.set(unsigned.flatMap(RewriteHardeningBundleTask::unsignedBundle))
            signedCandidate.set(
                project.layout.buildDirectory.file(
                    invocationDirectory.map { directory -> "$directory/signed-candidate.aab" },
                ),
            )
            artifactBoundary.set(project.layout.buildDirectory)
            useSigningMaterial(material)
            configureInternalGuard(extension, bundleCommand)
        }
        val validated = project.tasks.register(
            "validateHardening${suffix}Bundle",
            ValidateHardeningBundleTask::class.java,
        ) {
            group = HARDENING_GROUP
            description = "Validates and atomically publishes the signed hardened $variant AAB."
            dependsOn(signed)
            variantName.set(variant)
            ordinaryBundle.set(bundleContext.ordinaryBundle)
            signedCandidate.set(signed.flatMap(SignHardeningBundleTask::signedCandidate))
            rewriteManifest.set(unsigned.flatMap(RewriteHardeningBundleTask::rewriteManifest))
            semanticResults.set(unsigned.flatMap(RewriteHardeningBundleTask::semanticResults))
            transformationReport.set(unsigned.flatMap(RewriteHardeningBundleTask::planReport))
            hardenedBundle.set(
                project.layout.buildDirectory.file(
                    invocationDirectory.map { directory -> "$directory/verified.aab" },
                ),
            )
            verificationReport.set(
                project.layout.buildDirectory.file(
                    invocationDirectory.map { directory -> "$directory/bundle-verification.json" },
                ),
            )
            artifactBoundary.set(project.layout.buildDirectory)
            this.saltService.set(saltService)
            usesService(saltService)
            configureInternalGuard(extension, bundleCommand)
        }
        tasks.verify.configure {
            dependsOn(validated)
            currentR8Mapping.set(bundleContext.obfuscationMapping)
            preparedR8Mapping.set(
                tasks.prepare.flatMap(PrepareHardeningTask::preparedDirectory).map { directory ->
                    directory.file("mapping.txt")
                },
            )
            hardenedBundle.set(validated.flatMap(ValidateHardeningBundleTask::hardenedBundle))
            transformationReport.set(unsigned.flatMap(RewriteHardeningBundleTask::planReport))
            bundleVerificationReport.set(validated.flatMap(ValidateHardeningBundleTask::verificationReport))
            mappingVerificationReport.set(
                project.layout.buildDirectory.file(
                    invocationDirectory.map { directory -> "$directory/mapping-verification.json" },
                ),
            )
        }
        tasks.archive.configure {
            hardenedBundle.set(validated.flatMap(ValidateHardeningBundleTask::hardenedBundle))
            verificationReport.set(validated.flatMap(ValidateHardeningBundleTask::verificationReport))
            mappingVerificationReport.set(tasks.verify.flatMap(VerifyHardeningTask::mappingVerificationReport))
        }
        tasks.bundle.configure {
            expectedArtifact.set(tasks.archive.flatMap(ArchiveHardeningTask::publishedBundle))
        }
        val universalApk = project.tasks.register(
            "assembleHardening${suffix}UniversalApk",
            AssembleHardeningUniversalApkTask::class.java,
        ) {
            group = HARDENING_GROUP
            description = "Builds and verifies a signed universal APK from the verified hardened $variant AAB."
            dependsOn(tasks.verify)
            variantName.set(variant)
            hardenedBundle.set(validated.flatMap(ValidateHardeningBundleTask::hardenedBundle))
            bundleVerificationReport.set(validated.flatMap(ValidateHardeningBundleTask::verificationReport))
            rewriteManifest.set(unsigned.flatMap(RewriteHardeningBundleTask::rewriteManifest))
            this.aapt2Executable.set(aapt2Executable)
            this.zipalignExecutable.set(zipalignExecutable)
            bundletoolWorkerClasspath.from(bundletoolWorkerRuntime, bundletoolWorkerImplementation)
            universalApk.set(
                project.layout.buildDirectory.file(
                    "outputs/hardening/$variant/${variant}-hardened-universal.apk",
                ),
            )
            universalApkVerificationReport.set(
                project.layout.buildDirectory.file(
                    "reports/hardening/$variant/universal-apk-verification.json",
                ),
            )
            artifactBoundary.set(project.layout.buildDirectory)
            this.lockService.set(lockService)
            this.saltService.set(saltService)
            useSigningMaterial(bundleContext.signingMaterial)
            usesService(lockService)
            usesService(saltService)
            configureInternalGuard(extension, assembleCommand)
        }
        tasks.assemble.configure {
            dependsOn(universalApk)
            expectedArtifact.set(universalApk.flatMap(AssembleHardeningUniversalApkTask::universalApk))
        }
        if (variant in extension.variants.included.get()) {
            val ordinaryUniversalApk = project.tasks.register(
                "assembleOrdinary${suffix}UniversalApk",
                AssembleOrdinaryUniversalApkTask::class.java,
            ) {
                group = HARDENING_GROUP
                description = "Builds a signed ordinary universal APK for $variant owned-artifact comparison."
                dependsOn(bundleContext.ordinaryBundle)
                ordinaryBundle.set(bundleContext.ordinaryBundle)
                this.aapt2Executable.set(aapt2Executable)
                bundletoolWorkerClasspath.from(bundletoolWorkerRuntime, bundletoolWorkerImplementation)
                this.universalApk.set(
                    project.layout.buildDirectory.file(
                        "outputs/hardening/$variant/${variant}-ordinary-universal.apk",
                    ),
                )
                artifactBoundary.set(project.layout.buildDirectory)
                useSigningMaterial(bundleContext.signingMaterial)
                configureInternalGuard(extension, bundleCommand)
            }
            val baselineRoot = extension.similarity.baselineDirectory.dir(
                extension.projectKey.map { projectKey -> "$projectKey/$variant/v1" },
            )
            requireNotNull(tasks.captureBaseline).configure {
                this.configurationSha256.set(configurationSha256)
                dependsOn(tasks.archive, ordinaryUniversalApk, universalApk)
                ordinaryBundle.set(bundleContext.ordinaryBundle)
                hardenedBundle.set(validated.flatMap(ValidateHardeningBundleTask::hardenedBundle))
                this.ordinaryUniversalApk.set(ordinaryUniversalApk.flatMap(AssembleOrdinaryUniversalApkTask::universalApk))
                hardenedUniversalApk.set(universalApk.flatMap(AssembleHardeningUniversalApkTask::universalApk))
                ownedArtifactInventory.set(unsigned.flatMap(RewriteHardeningBundleTask::ownedArtifactInventory))
                ownedArtifactAnalysisInventory.set(
                    unsigned.flatMap(RewriteHardeningBundleTask::ownedArtifactAnalysisInventory),
                )
                this.baselineRoot.set(baselineRoot)
            }
            requireNotNull(tasks.compare).configure {
                this.configurationSha256.set(configurationSha256)
                dependsOn(ordinaryUniversalApk, universalApk)
                ordinaryBundle.set(bundleContext.ordinaryBundle)
                hardenedBundle.set(validated.flatMap(ValidateHardeningBundleTask::hardenedBundle))
                this.ordinaryUniversalApk.set(ordinaryUniversalApk.flatMap(AssembleOrdinaryUniversalApkTask::universalApk))
                hardenedUniversalApk.set(universalApk.flatMap(AssembleHardeningUniversalApkTask::universalApk))
                ownedArtifactInventory.set(unsigned.flatMap(RewriteHardeningBundleTask::ownedArtifactInventory))
                ownedArtifactAnalysisInventory.set(
                    unsigned.flatMap(RewriteHardeningBundleTask::ownedArtifactAnalysisInventory),
                )
                currentR8Mapping.set(bundleContext.obfuscationMapping)
                mappingStoreDirectory.set(extension.mapping.storeDirectory)
                this.baselineRoot.set(baselineRoot)
            }
            requireNotNull(tasks.smoke).configure {
                hardenedUniversalApk.set(
                    project.layout.buildDirectory.file(
                        "outputs/hardening/$variant/${variant}-hardened-universal.apk",
                    ),
                )
                sdkDirectory.set(androidComponents.sdkComponents.sdkDirectory)
            }
            requireNotNull(tasks.run).configure {
                expectedArtifact.set(universalApk.flatMap(AssembleHardeningUniversalApkTask::universalApk))
            }
        }
        return HardeningBundlePipelineTasks(unsigned, validated, universalApk)
    }

    private fun Task.configureInternalGuard(extension: AndroidHardeningExtension, correctedCommand: String) {
        onlyIf("androidHardening is enabled or this task was directly requested") {
            if (extension.enabled.get()) {
                true
            } else if (project.gradle.startParameter.taskNames.any { requested -> requested.substringAfterLast(':') == name }) {
                throw GradleException("Android hardening is disabled. Run exactly:\n$correctedCommand")
            } else {
                false
            }
        }
    }

    private companion object {
        const val BUNDLETOOL_WORKER_CONFIGURATION = "androidHardeningBundletoolWorkerRuntime"
        const val HARDENING_GROUP = "hardening"
    }
}

private fun zipalignExecutableName(): String =
    if (System.getProperty("os.name").contains("win", ignoreCase = true)) "zipalign.exe" else "zipalign"

private fun configurationSchema(@Suppress("UNUSED_PARAMETER") variant: String): String =
    "r8-owned-code-registry-v4-portable"
