package com.holin.android.hardening

import com.android.build.api.artifact.ScopedArtifact
import com.android.build.api.artifact.SingleArtifact
import com.android.build.api.variant.ApplicationVariant
import com.android.build.api.variant.ScopedArtifacts
import com.holin.android.hardening.tasks.GenerateHardeningJunkCodeTask
import com.holin.android.hardening.tasks.MergeHardeningJunkManifestTask
import com.holin.android.hardening.tasks.InjectHardeningJunkCallsTask
import org.gradle.api.Project

internal object JunkCodeWiring {
    fun wire(project: Project, extension: AndroidHardeningExtension, variant: ApplicationVariant, tasks: HardeningVariantTasks) {
        if (!extension.junkCode.enabled.get()) return
        AgpPublicCapabilityProbe.verifyJunkCode(
            ProjectToolchainInspector.inspect(project).androidGradlePlugin,
            requireNotNull(project.plugins.findPlugin("com.android.application")).javaClass.classLoader,
        )
        val suffix = HardeningNames.taskSuffix(variant.name)
        val resources = requireNotNull(variant.sources.res) { "junkCode requires Android resource sources" }
        val invocationSalt = tasks.invocationSalt
        val generated = project.tasks.register("generateHardening${suffix}JunkCode", GenerateHardeningJunkCodeTask::class.java) {
            group = "hardening"
            description = "Generates isolated bytecode, resources and disabled Activities for ${variant.name}."
            namespace.set(variant.namespace)
            variantName.set(variant.name)
            policy.set(project.providers.provider { extension.junkCode.policy().encode() })
            lineageSeed.set(tasks.prepare.flatMap { it.preparedDirectory.file("seed.bin") })
            saltService.set(invocationSalt)
            usesService(invocationSalt)
            artifactBoundary.set(project.layout.buildDirectory)
            outputDirectory.set(project.layout.buildDirectory.dir("intermediates/hardening/${variant.name}/junk-code"))
            scratchDirectory.set(tasks.prepare.flatMap { it.preparedDirectory }.map { directory ->
                directory.dir("../invocations/${directory.asFile.name.removePrefix("prepared-")}/scratch/junk-code")
            })
            classesJar.set(outputDirectory.file("classes.jar"))
            resourceDirectory.set(outputDirectory.dir("res"))
            manifestFile.set(outputDirectory.file("AndroidManifest.xml"))
            keepRules.set(outputDirectory.file("keep.pro"))
            generationReport.set(project.layout.buildDirectory.file("reports/hardening/${variant.name}/junk-code-generation.json"))
        }
        variant.artifacts.forScope(ScopedArtifacts.Scope.PROJECT).use(generated)
            .toAppend(ScopedArtifact.CLASSES, GenerateHardeningJunkCodeTask::classesJar)
        resources.addGeneratedSourceDirectory(generated, GenerateHardeningJunkCodeTask::resourceDirectory)
        variant.proguardFiles.add(generated.flatMap { it.keepRules })
        val manifest = project.tasks.register("mergeHardening${suffix}JunkManifest", MergeHardeningJunkManifestTask::class.java) {
            group = "hardening"
            fragment.set(generated.flatMap { it.manifestFile })
            inventory.set(generated.flatMap { it.generationReport })
            generatedResources.set(generated.flatMap { it.resourceDirectory })
            resourceInputs.from(project.files(resources.all).asFileTree)
            resourceInputs.from(project.providers.provider {
                extension.ownership.resolve(project.rootProject).modules.flatMap { it.sourceRoots.resourceDirectories }
                    .map { project.fileTree(it) }
            })
            dependencyInputs.from(project.configurations.getByName("${variant.name}RuntimeClasspath")
                .incoming.artifactView {
                    componentFilter { it !is org.gradle.api.artifacts.component.ProjectComponentIdentifier }
                }.files)
            outputManifest.set(project.layout.buildDirectory.file("intermediates/hardening/${variant.name}/junk-manifest/AndroidManifest.xml"))
        }
        variant.artifacts.use(manifest).wiredWithFiles(MergeHardeningJunkManifestTask::inputManifest, MergeHardeningJunkManifestTask::outputManifest)
            .toTransform(SingleArtifact.MERGED_MANIFEST)
        val calls = project.tasks.register("injectHardening${suffix}JunkCalls", InjectHardeningJunkCallsTask::class.java) {
            group = "hardening"
            description = "Connects generated computation to the Application constructor for ${variant.name}."
            inventory.set(generated.flatMap { it.generationReport })
            inputManifest.set(manifest.flatMap { it.outputManifest })
            inputJars.convention(emptyList())
            inputDirectories.convention(emptyList())
            outputJar.set(project.layout.buildDirectory.file("intermediates/hardening/${variant.name}/junk-calls/classes.jar"))
            report.set(project.layout.buildDirectory.file("reports/hardening/${variant.name}/junk-code-calls.json"))
        }
        variant.artifacts.forScope(ScopedArtifacts.Scope.ALL).use(calls).toTransform(ScopedArtifact.CLASSES,
            InjectHardeningJunkCallsTask::inputJars, InjectHardeningJunkCallsTask::inputDirectories, InjectHardeningJunkCallsTask::outputJar)
        tasks.verify.configure {
            junkCodeInventory.set(generated.flatMap { it.generationReport })
            junkCodeVerificationReport.set(project.layout.buildDirectory.file("reports/hardening/${variant.name}/junk-code-aab-verification.json"))
        }
        requireNotNull(tasks.pipeline).universalApk.configure {
            junkCodeInventory.set(generated.flatMap { it.generationReport })
            junkCodeVerificationReport.set(project.layout.buildDirectory.file("reports/hardening/${variant.name}/junk-code-apk-verification.json"))
        }
    }
}
