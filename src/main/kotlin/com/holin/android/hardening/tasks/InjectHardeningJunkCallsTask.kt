package com.holin.android.hardening.tasks

import com.holin.android.hardening.junk.JunkApplicationBootstrap
import com.holin.android.hardening.junk.JunkCodeInventory
import com.holin.android.hardening.junk.JunkManifest
import com.holin.android.hardening.state.AtomicFiles
import com.holin.android.hardening.state.Sha256
import groovy.json.JsonOutput
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import org.gradle.api.DefaultTask
import org.gradle.api.file.Directory
import org.gradle.api.file.RegularFile
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault

@DisableCachingByDefault
abstract class InjectHardeningJunkCallsTask : DefaultTask() {
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val inputJars: ListProperty<RegularFile>
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val inputDirectories: ListProperty<Directory>
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val inputManifest: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val inventory: RegularFileProperty
    @get:OutputFile abstract val outputJar: RegularFileProperty
    @get:OutputFile abstract val report: RegularFileProperty

    @TaskAction fun inject() {
        val payload = JunkCodeInventory.read(inventory.get().asFile.toPath())
        val entries = sortedMapOf<String, ByteArray>()
        fun add(name: String, bytes: ByteArray) {
            require(!name.startsWith('/') && name.split('/').none { it == "." || it == ".." }) { "invalid junkCode program entry" }
            require(entries.putIfAbsent(name, bytes) == null) { "junkCode found duplicate program class: $name" }
        }
        inputJars.get().sortedBy { it.asFile.path }.forEach { jar -> ZipFile(jar.asFile).use { zip ->
            zip.entries().asSequence().filter { it.name.endsWith(".class") && it.name != "module-info.class" && !it.name.startsWith("META-INF/") }
                .forEach { entry -> add(entry.name, zip.getInputStream(entry).use { it.readBytes() }) }
        } }
        inputDirectories.get().sortedBy { it.asFile.path }.forEach { directory ->
            Files.walk(directory.asFile.toPath()).use { paths -> paths.forEach { path ->
                require(!Files.isSymbolicLink(path)) { "symbolic junkCode program input" }
                if (Files.isRegularFile(path) && path.toString().endsWith(".class")) {
                    add(directory.asFile.toPath().relativize(path).toString().replace('\\', '/'), Files.readAllBytes(path))
                }
            } }
        }
        val evidence = linkedMapOf<String, Any?>("schemaVersion" to 1, "status" to "SKIPPED_NO_METHODS",
            "inventorySha256" to Sha256.file(inventory.get().asFile.toPath()), "insertedCalls" to 0)
        payload.runtime?.let { runtime ->
            val application = JunkManifest.applicationName(inputManifest.get().asFile.readBytes())
            val path = application.replace('.', '/') + ".class"
            val original = requireNotNull(entries[path]) {
                "junkCode requires an instrumentable Application class: $application"
            }
            val generatedApplication = application == runtime.entryClass
            val injection = if (generatedApplication) null else JunkApplicationBootstrap.install(original, runtime.entryClass)
            val changed = injection?.bytes ?: original
            entries[path] = changed
            evidence.putAll(linkedMapOf("status" to "PASS", "applicationClass" to application, "entryClass" to runtime.entryClass,
                "generatedApplication" to generatedApplication, "insertedCalls" to (injection?.calls ?: 0),
                "constructorInverseProof" to if (generatedApplication) "NOT_APPLICABLE_GENERATED" else "PASS",
                "applicationInputSha256" to Sha256.hex(original), "applicationOutputSha256" to Sha256.hex(changed),
                "generatedMethods" to payload.classes.sumOf { it.methods.size }, "runtimeClasses" to runtime.groups.size))
        }
        val buffer = ByteArrayOutputStream()
        ZipOutputStream(buffer).use { zip -> entries.forEach { (name, bytes) ->
            zip.putNextEntry(ZipEntry(name).apply { time = 0L }); zip.write(bytes); zip.closeEntry()
        } }
        val output = buffer.toByteArray()
        AtomicFiles().replace(outputJar.get().asFile.toPath(), output)
        evidence["outputJarSha256"] = Sha256.hex(output)
        AtomicFiles().replace(report.get().asFile.toPath(), (JsonOutput.toJson(evidence) + "\n").toByteArray())
    }
}
