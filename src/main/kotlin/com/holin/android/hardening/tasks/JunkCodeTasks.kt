package com.holin.android.hardening.tasks

import com.holin.android.hardening.artifact.ArtifactPathBoundary
import com.holin.android.hardening.junk.JunkCodeGenerator
import com.holin.android.hardening.junk.JunkCodeInventory
import com.holin.android.hardening.junk.JunkCodePolicy
import com.holin.android.hardening.junk.JunkManifest
import com.holin.android.hardening.state.AtomicFiles
import com.holin.android.hardening.state.InvocationSaltService
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.util.zip.ZipFile
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault
import org.w3c.dom.Element

// Generated content uses invocation-local hardening entropy.
@DisableCachingByDefault
abstract class GenerateHardeningJunkCodeTask : DefaultTask() {
    @get:Input abstract val namespace: Property<String>
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val policy: Property<String>
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val lineageSeed: RegularFileProperty
    @get:Internal abstract val saltService: Property<InvocationSaltService>
    @get:Internal abstract val artifactBoundary: DirectoryProperty
    @get:Internal abstract val scratchDirectory: DirectoryProperty
    @get:OutputDirectory abstract val outputDirectory: DirectoryProperty
    @get:OutputFile abstract val generationReport: RegularFileProperty
    // toAppend assigns its own location. Always publish to the property supplied by AGP.
    @get:OutputFile abstract val classesJar: RegularFileProperty
    @get:OutputDirectory abstract val resourceDirectory: DirectoryProperty
    @get:Internal abstract val manifestFile: RegularFileProperty
    @get:Internal abstract val keepRules: RegularFileProperty

    init { outputs.upToDateWhen { false } }

    @TaskAction
    fun generate() {
        val paths = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
        val output = paths.requireSafePath(outputDirectory.get().asFile.toPath())
        val scratch = paths.requireSafePath(scratchDirectory.get().asFile.toPath())
        val seed = Files.readAllBytes(paths.requireInput(lineageSeed.get().asFile.toPath()))
        try {
            removeOwnedDirectory(scratch, paths)
            val inventory = saltService.get().withSalt { salt ->
                JunkCodeGenerator.generate(JunkCodePolicy.decode(policy.get()), namespace.get(), variantName.get(), seed, salt, scratch)
            }
            removeOwnedDirectory(output, paths)
            Files.createDirectories(output.parent)
            Files.move(scratch, output, ATOMIC_MOVE)
            val jar = paths.prepareOutput(classesJar.get().asFile.toPath())
            if (jar != output.resolve("classes.jar")) {
                AtomicFiles().replace(jar, Files.readAllBytes(output.resolve("classes.jar")))
            }
            // AGP 8.8/8.10 assign a generated resource directory even when one was configured.
            val resources = paths.requireSafePath(resourceDirectory.get().asFile.toPath())
            if (resources != output.resolve("res")) {
                removeOwnedDirectory(resources, paths)
                Files.walk(output.resolve("res")).use { entries ->
                    entries.forEach { source ->
                        val target = paths.requireSafePath(resources.resolve(output.resolve("res").relativize(source)))
                        if (Files.isDirectory(source)) Files.createDirectories(target) else Files.copy(source, target)
                    }
                }
            }
            AtomicFiles().replace(paths.prepareOutput(generationReport.get().asFile.toPath()), inventory.encode().toByteArray())
        } finally {
            seed.fill(0)
            removeOwnedDirectory(scratch, paths)
        }
    }

    private fun removeOwnedDirectory(directory: Path, paths: ArtifactPathBoundary) {
        if (!Files.exists(directory)) return
        val entries = Files.walk(directory).use { it.toList() }
        entries.forEach(paths::requireSafePath)
        entries.sortedDescending().forEach(Files::delete)
    }
}

@DisableCachingByDefault
abstract class MergeHardeningJunkManifestTask : DefaultTask() {
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val inputManifest: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val fragment: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val inventory: RegularFileProperty
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val resourceInputs: ConfigurableFileCollection
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val dependencyInputs: ConfigurableFileCollection
    @get:Internal abstract val generatedResources: DirectoryProperty
    @get:OutputFile abstract val outputManifest: RegularFileProperty

    @TaskAction
    fun merge() {
        val generated = generatedResources.get().asFile.toPath().toAbsolutePath().normalize()
        val payload = JunkCodeInventory.read(inventory.get().asFile.toPath())
        val expected = payload.resources.map { it.type to it.name }.toSet()
        resourceInputs.asFileTree.files.sortedBy { it.path }.forEach { file ->
            val path = file.toPath().toAbsolutePath().normalize()
            if (path.startsWith(generated)) return@forEach
            checkResource("${file.parentFile.name}/${file.name}", expected, path.toString()) { Files.readAllBytes(path) }
        }
        dependencyInputs.files.filter { it.isFile && it.extension == "aar" }.sortedBy { it.path }.forEach { aar ->
            ZipFile(aar).use { zip ->
                zip.entries().asSequence().filter { !it.isDirectory && it.name.startsWith("res/") }.forEach { entry ->
                    checkResource(entry.name.removePrefix("res/"), expected, "${aar.name}!/${entry.name}") {
                        zip.getInputStream(entry).use { it.readBytes() }
                    }
                }
            }
        }
        val merged = JunkManifest.merge(Files.readAllBytes(inputManifest.get().asFile.toPath()),
            Files.readAllBytes(fragment.get().asFile.toPath()), payload.runtime)
        AtomicFiles().replace(outputManifest.get().asFile.toPath(), merged)
    }

    private fun checkResource(relative: String, expected: Set<Pair<String, String>>, source: String, bytes: () -> ByteArray) {
        val type = relative.substringBefore('/').substringBefore('-')
        val name = relative.substringAfterLast('/')
        if (type == "values" && name.endsWith(".xml")) {
            val root = JunkManifest.parse(bytes()).documentElement
            (0 until root.childNodes.length).mapNotNull { root.childNodes.item(it) as? Element }.forEach { item ->
                val resourceType = if (item.tagName == "item") item.getAttribute("type") else item.tagName
                require(resourceType to item.getAttribute("name") !in expected) { "junkCode resource conflicts with $source" }
            }
        } else {
            require(type to name.substringBeforeLast('.').removeSuffix(".9") !in expected) {
                "junkCode resource conflicts with $source"
            }
        }
    }
}
