package com.holin.android.hardening.tasks

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.inventory.OwnedDexInventoryBuilder
import com.holin.android.hardening.code.OwnedClassStringRulesRenderer
import com.holin.android.hardening.r8.HardeningRuleManifestCodec
import com.holin.android.hardening.r8.HardeningRulesFilter
import com.holin.android.hardening.state.StrictJson
import java.nio.file.Files
import java.nio.file.Path
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault

@DisableCachingByDefault(because = "The generated rules are scoped to an explicit local hardening invocation")
abstract class GenerateHardeningR8RulesTask : DefaultTask() {
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val sourceOccurrenceCount: Property<Int>
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sourceRules: ConfigurableFileCollection
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val preserveExactRules: ConfigurableFileCollection
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val additionalRules: ConfigurableFileCollection
    @get:Internal abstract val repositoryRoot: DirectoryProperty
    @get:Internal abstract val ownership: Property<HardeningOwnership>
    @get:OutputFile abstract val filteredRules: RegularFileProperty
    @get:OutputFile abstract val decisionManifest: RegularFileProperty

    @TaskAction
    fun generate() {
        val occurrenceCount = sourceOccurrenceCount.get()
        require(occurrenceCount > 0) { "the app ProGuard file was not present in the selected variant" }
        val sources = sourceRules.files.map { it.toPath().toAbsolutePath().normalize() }.sortedBy(Path::toString)
        require(sources.size == occurrenceCount) {
            "declared ProGuard source count ${sources.size} differs from occurrence count $occurrenceCount"
        }
        val preserved = preserveExactRules.files.map { it.toPath().toAbsolutePath().normalize() }
            .sortedBy(Path::toString)
        val additional = additionalRules.files.map { it.toPath().toAbsolutePath().normalize() }
            .sortedBy(Path::toString)
        val sourceText = readRules(sources, "source")
        val preservedText = readRules(preserved, "preserved")
        val additionalText = readRules(additional, "additional")
        val ownedSourceDescriptors = OwnedDexInventoryBuilder(
            repositoryRoot.get().asFile.toPath(),
            ownership.get(),
        ).sourceInventory().map { it.originalDescriptor }
        val ownedPackageRoots = ownedSourceDescriptors.mapNotNull { descriptor ->
            descriptor.removePrefix("L").removeSuffix(";")
                .substringBeforeLast('/', "")
                .replace('/', '.')
                .takeIf(String::isNotEmpty)
        }.toSet()
        val generatedClassStringRules = OwnedClassStringRulesRenderer().render(ownedSourceDescriptors)
        val effectiveAdditionalRules = buildString {
            append(additionalText)
            if (isNotEmpty() && !endsWith('\n')) append('\n')
            append(generatedClassStringRules)
        }
        val filtered = HardeningRulesFilter.filter(
            sourceText,
            ownedPackageRoots,
            preservedText,
            effectiveAdditionalRules,
        )
        val filteredPath = filteredRules.get().asFile.toPath()
        Files.createDirectories(requireNotNull(filteredPath.parent))
        Files.writeString(filteredPath, filtered.effectiveRules)
        val report = HardeningRuleManifestCodec.encode(
            variantName.get(),
            sources.joinToString("|") { project.relativePath(it.toFile()) },
            project.relativePath(filteredPath.toFile()),
            true,
            occurrenceCount,
            filtered.manifest,
        )
        StrictJson.validateDocument(report)
        val reportPath = decisionManifest.get().asFile.toPath()
        Files.createDirectories(requireNotNull(reportPath.parent))
        Files.writeString(reportPath, report)
    }

    private fun readRules(paths: List<java.nio.file.Path>, label: String): String = paths.joinToString("\n") { path ->
        require(Files.isRegularFile(path) && !Files.isSymbolicLink(path)) {
            "$label ProGuard rule file is missing or unsafe: $path"
        }
        Files.readString(path)
    }
}
