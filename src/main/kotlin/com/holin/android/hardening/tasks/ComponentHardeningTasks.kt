package com.holin.android.hardening.tasks

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.components.ComponentPolicy
import com.holin.android.hardening.components.ComponentRelocation
import com.holin.android.hardening.components.PreR8Relocation
import com.holin.android.hardening.inventory.OwnedDexInventoryBuilder
import com.holin.android.hardening.state.Sha256
import groovy.json.JsonOutput
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.Directory
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFile
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault
import org.objectweb.asm.ClassReader
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

@DisableCachingByDefault
abstract class RelocateHardeningManifestTask : DefaultTask() {
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val inputManifest: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val lineageSeed: RegularFileProperty
    @get:Input abstract val policy: Property<String>
    @get:Input abstract val namespace: Property<String>
    @get:Internal abstract val repositoryRoot: DirectoryProperty
    @get:Internal abstract val ownership: Property<HardeningOwnership>
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val sourceInputs: ConfigurableFileCollection
    @get:Input abstract val sourceOwnership: ListProperty<String>
    @get:OutputFile abstract val outputManifest: RegularFileProperty
    @get:OutputFile abstract val relocationPlan: RegularFileProperty
    @get:OutputFile abstract val report: RegularFileProperty

    @TaskAction fun relocate() {
        val sources = sourceInputs.files.filter { it.isFile && it.extension in setOf("kt", "java") }
            .associate { it.relativeTo(repositoryRoot.get().asFile).invariantSeparatorsPath to it.readText() }
        val xml = sourceInputs.files.filter { it.isFile && it.extension == "xml" && it.name != "AndroidManifest.xml" }
            .associate { it.relativeTo(repositoryRoot.get().asFile).invariantSeparatorsPath to it.readText() }
        val owned = OwnedDexInventoryBuilder(repositoryRoot.get().asFile.toPath(), ownership.get()).sourceInventory()
            .mapTo(linkedSetOf()) { it.originalDescriptor.removePrefix("L").removeSuffix(";") }
        val result = ComponentRelocation.plan(inputManifest.get().asFile.readBytes(), namespace.get(), ComponentPolicy.decode(policy.get()),
            lineageSeed.get().asFile.readBytes(), owned, sources, xml)
        outputManifest.get().asFile.apply { parentFile.mkdirs(); writeBytes(result.manifest) }
        relocationPlan.get().asFile.apply { parentFile.mkdirs(); writeText(JsonOutput.toJson(mapOf("schemaVersion" to 1,
            "relocations" to result.relocations, "policySha256" to Sha256.hex(policy.get().toByteArray())))) }
        report.get().asFile.apply { parentFile.mkdirs(); writeText(JsonOutput.prettyPrint(JsonOutput.toJson(result.report))) }
    }
}

@DisableCachingByDefault
abstract class RelocateHardeningClassesTask : DefaultTask() {
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val inputJars: ListProperty<RegularFile>
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val inputDirectories: ListProperty<Directory>
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val externalClasses: ConfigurableFileCollection
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val relocationPlan: RegularFileProperty
    @get:OutputFile abstract val outputJar: RegularFileProperty
    @get:OutputFile abstract val report: RegularFileProperty

    @TaskAction fun relocate() {
        val mapping = PreR8Relocation.readPlan(relocationPlan.get().asFile.readText())
        val entries = sortedMapOf<String, ByteArray>()
        fun collect(name: String, bytes: ByteArray) {
            require(name.isNotBlank() && !name.startsWith('/') && name.split('/').none { it == ".." || it == "." })
            if (name.startsWith("META-INF/") && (name.endsWith(".SF") || name.endsWith(".RSA") || name.endsWith(".DSA"))) {
                error("signed project class artifact cannot be relocated")
            }
            val previous = entries.putIfAbsent(name, bytes)
            require(previous == null || previous.contentEquals(bytes)) { "conflicting project class entry: $name" }
        }
        inputJars.get().forEach { file -> ZipFile(file.asFile).use { zip ->
            zip.entries().asSequence().filterNot { it.isDirectory }.forEach { entry ->
                collect(entry.name, zip.getInputStream(entry).use { it.readBytes() })
            }
        } }
        inputDirectories.get().forEach { directory -> Files.walk(directory.asFile.toPath()).use { paths ->
            paths.forEach { file ->
                require(!Files.isSymbolicLink(file)) { "symbolic project class input" }
                if (Files.isRegularFile(file)) collect(directory.asFile.toPath().relativize(file).toString().replace('\\', '/'), Files.readAllBytes(file))
            }
        } }
        if (mapping.isNotEmpty()) {
            val references = mapping.keys.flatMap { listOf(it, it.replace('/', '.')) }
            externalClasses.files.filter { it.isFile && it.extension == "jar" }.forEach { file -> ZipFile(file).use { zip ->
                zip.entries().asSequence().filterNot { it.isDirectory }.forEach { entry ->
                    val text = zip.getInputStream(entry).use { it.readBytes() }.toString(Charsets.ISO_8859_1)
                    require(references.none { it in text }) { "external artifact ${file.name}:${entry.name} references a relocated component" }
                }
            } }
            require(mapping.keys.all { "$it.class" in entries }) { "component class absent from project artifact" }
            require(mapping.values.none { "$it.class" in entries }) { "component output class already exists" }
        }
        val rows = mutableListOf<Map<String, Any>>()
        val outputNames = linkedSetOf<String>()
        val output = outputJar.get().asFile.apply { parentFile.mkdirs() }
        ZipOutputStream(output.outputStream().buffered()).use { zip -> entries.forEach { (name, bytes) ->
            var outName = name
            val after = if (name.endsWith(".class")) {
                require(ClassReader(bytes).className + ".class" == name)
                PreR8Relocation.requireClosedStrings(bytes, mapping)
                PreR8Relocation.transform(bytes, mapping).also { transformed ->
                    if (mapping.isNotEmpty()) PreR8Relocation.verify(bytes, transformed, mapping)
                    outName = ClassReader(transformed).className + ".class"
                    if (!bytes.contentEquals(transformed)) rows += mapOf("source" to name, "output" to outName,
                        "sourceSha256" to Sha256.hex(bytes), "outputSha256" to Sha256.hex(transformed), "inverseProof" to true)
                }
            } else {
                require(mapping.keys.none { it in bytes.toString(Charsets.ISO_8859_1) || it.replace('/', '.') in bytes.toString(Charsets.ISO_8859_1) }) {
                    "component identity in unsupported class metadata: $name"
                }
                bytes
            }
            require(outputNames.add(outName)) { "relocated class entry collision" }
            zip.putNextEntry(ZipEntry(outName).apply { time = 0 })
            zip.write(after)
            zip.closeEntry()
        } }
        report.get().asFile.apply { parentFile.mkdirs(); writeText(JsonOutput.prettyPrint(JsonOutput.toJson(mapOf(
            "schemaVersion" to 1, "components" to mapping, "verifiedClassCount" to entries.keys.count { it.endsWith(".class") },
            "changedClassEntries" to rows, "outputSha256" to Sha256.file(output.toPath()))))) }
    }
}

@DisableCachingByDefault
abstract class ComposeHardeningMappingTask : DefaultTask() {
    @get:Input abstract val requireMappedClasses: Property<Boolean>
    init { requireMappedClasses.convention(true) }
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val inputMapping: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val relocationPlan: RegularFileProperty
    @get:OutputFile abstract val outputMapping: RegularFileProperty
    @get:OutputFile abstract val report: RegularFileProperty

    @TaskAction fun compose() {
        val aliases = PreR8Relocation.readPlan(relocationPlan.get().asFile.readText())
        val original = inputMapping.get().asFile.readText()
        if (requireMappedClasses.get()) aliases.values.forEach { alias ->
            require(original.lineSequence().any { it.startsWith(alias.replace('/', '.') + " -> ") }) { "R8 omitted a relocated manifest component" }
        }
        val inverse = aliases.entries.associate { it.value to it.key }
        val transformed = if (aliases.isEmpty()) original else PreR8Relocation.rewriteMappingLeft(original, inverse)
        require(aliases.isEmpty() || PreR8Relocation.rewriteMappingLeft(transformed, aliases) == original) { "R8 mapping inverse proof failed" }
        outputMapping.get().asFile.apply { parentFile.mkdirs(); writeText(transformed) }
        report.get().asFile.apply { parentFile.mkdirs(); writeText(JsonOutput.toJson(mapOf("schemaVersion" to 1,
            "sourceSha256" to Sha256.hex(original.toByteArray()), "outputSha256" to Sha256.hex(transformed.toByteArray()),
            "classCount" to aliases.size, "inverseProof" to true))) }
    }
}
