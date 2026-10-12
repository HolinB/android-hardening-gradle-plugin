package com.holin.android.hardening.tasks

import com.holin.android.hardening.dependencies.DependencyCandidate
import com.holin.android.hardening.dependencies.DependencyPolicy
import com.holin.android.hardening.dependencies.DependencyProtection
import com.holin.android.hardening.state.Sha256
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.gradle.api.DefaultTask
import org.gradle.api.file.*
import org.gradle.api.provider.*
import org.gradle.api.tasks.*
import org.gradle.work.DisableCachingByDefault
import org.objectweb.asm.ClassReader
import java.io.File
import java.nio.file.Files
import java.util.zip.*

@DisableCachingByDefault
abstract class DependencyHardeningTask : DefaultTask() {
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val inputJars: ListProperty<RegularFile>
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val inputDirectories: ListProperty<Directory>
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val dependencyInputs: ConfigurableFileCollection
    @get:Input abstract val artifactMetadata: ListProperty<String>
    @get:Input abstract val policy: Property<String>
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val lineageSeed: RegularFileProperty
    @get:OutputFile abstract val outputJar: RegularFileProperty
    @get:OutputFile abstract val relocationPlan: RegularFileProperty
    @get:OutputFile abstract val report: RegularFileProperty
    @get:OutputDirectory abstract val derivedArtifacts: DirectoryProperty

    @TaskAction fun transform() {
        val selectedPolicy = DependencyPolicy.decode(policy.get())
        val sources = dependencyInputs.files.filter { it.isFile }.associateWith { Sha256.file(it.toPath()) }
        val classes = sortedMapOf<String, ByteArray>()
        fun collect(path: String, bytes: ByteArray) {
            if (!path.endsWith(".class")) return
            val name = ClassReader(bytes).className
            require(path == "$name.class") { "noncanonical scoped class: $path" }
            val old = classes.putIfAbsent(name, bytes)
            require(old == null || old.contentEquals(bytes)) { "conflicting scoped class: $name" }
        }
        inputJars.get().forEach { jar -> entries(jar.asFile).forEach(::collect) }
        inputDirectories.get().forEach { directory -> Files.walk(directory.asFile.toPath()).use { paths -> paths.forEach { path ->
            require(!Files.isSymbolicLink(path))
            if (Files.isRegularFile(path)) collect(directory.asFile.toPath().relativize(path).toString().replace('\\', '/'), Files.readAllBytes(path))
        } } }
        val metadata = artifactMetadata.get().map { JsonSlurper().parseText(it) as Map<*, *> }
        val provenance = metadata.map { item ->
            val original = File(item["original"] as String)
            val effective = File(item["classes"] as String)
            mapOf("coordinate" to item["coordinate"], "originalFile" to original.name, "originalSha256" to sources.getValue(original),
                "originalBytes" to original.length(), "effectiveClassSha256" to sources.getValue(effective), "effectiveClassBytes" to effective.length(), "effectiveClassCount" to ZipFile(effective).use { zip -> zip.entries().asSequence().count { it.name.endsWith(".class") } })
        }
        val candidates = metadata.map { item ->
            val original = File(item["original"] as String)
            val effective = File(item["classes"] as String)
            val coordinate = item["coordinate"] as String
            val selected = coordinate in selectedPolicy.includes && coordinate !in selectedPolicy.excludes
            DependencyCandidate(coordinate, if (selected) entries(original) else emptyMap(),
                if (selected) entries(effective).filterKeys { it.endsWith(".class") }.mapKeys { ClassReader(it.value).className } else emptyMap(), original.extension == "jar")
        }
        val result = DependencyProtection.plan(classes, candidates, selectedPolicy, lineageSeed.get().asFile.readBytes())
        writeJar(outputJar.get().asFile, result.entries)
        val derivedRoot = derivedArtifacts.get().asFile.apply { mkdirs() }
        // This directory belongs solely to the task. Replace only its previous derived JARs.
        derivedRoot.listFiles()?.filter { it.isFile && it.name.endsWith(".jar") }?.forEach { require(it.delete()) }
        val derived = candidates.filter { candidate -> candidate.classes.keys.any { it in result.aliases } }.map { candidate ->
            val file = File(derivedRoot, Sha256.hex(candidate.coordinate.toByteArray()).take(24) + ".jar")
            writeJar(file, candidate.classes.keys.associate { original ->
                val name = result.aliases[original] ?: original
                name to result.entries.getValue(name)
            })
            mapOf("coordinate" to candidate.coordinate, "file" to file.name, "sha256" to Sha256.file(file.toPath()))
        }
        require(sources.all { (file, hash) -> Sha256.file(file.toPath()) == hash }) { "dependency input changed while deriving classes" }
        relocationPlan.get().asFile.apply { parentFile.mkdirs(); writeText(JsonOutput.toJson(mapOf("schemaVersion" to 1, "relocations" to result.aliases))) }
        report.get().asFile.apply { parentFile.mkdirs(); writeText(JsonOutput.prettyPrint(JsonOutput.toJson(result.report + mapOf(
            "provenance" to provenance, "derivedArtifacts" to derived, "scopedClassCount" to classes.size,
            "originalInputsUnchanged" to true, "outputSha256" to Sha256.file(outputJar.get().asFile.toPath()))))) }
    }

    private fun entries(file: File): Map<String, ByteArray> = ZipFile(file).use { zip ->
        val result = linkedMapOf<String, ByteArray>()
        zip.entries().asSequence().filterNot { it.isDirectory }.forEach { entry ->
            require(!entry.name.startsWith('/') && entry.name.split('/').none { it == ".." || it == "." })
            require(result.put(entry.name, zip.getInputStream(entry).use { it.readBytes() }) == null) { "duplicate dependency entry" }
        }
        result
    }
    private fun writeJar(file: File, classes: Map<String, ByteArray>) {
        file.parentFile.mkdirs()
        ZipOutputStream(file.outputStream().buffered()).use { zip -> classes.toSortedMap().forEach { (name, bytes) ->
            zip.putNextEntry(ZipEntry("$name.class").apply { time = 0 }); zip.write(bytes); zip.closeEntry()
        } }
    }
}
