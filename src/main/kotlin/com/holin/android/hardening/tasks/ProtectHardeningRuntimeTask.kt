package com.holin.android.hardening.tasks

import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.inventory.OwnedDexInventoryBuilder
import com.holin.android.hardening.runtime.RuntimeBytecodeAdapter
import com.holin.android.hardening.runtime.RuntimeEnvelope
import com.holin.android.hardening.runtime.RuntimeProtectionPolicy
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
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault
import java.nio.file.Files
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.tools.ToolProvider

@DisableCachingByDefault
abstract class ProtectHardeningRuntimeTask : DefaultTask() {
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val inputJars: ListProperty<RegularFile>
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val inputDirectories: ListProperty<Directory>
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val classpath: ConfigurableFileCollection
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val bootClasspath: ConfigurableFileCollection
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val sourceInputs: ConfigurableFileCollection
    @get:Input abstract val sourceOwnership: ListProperty<String>
    @get:Input abstract val namespace: Property<String>
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val minimumSdk: Property<Int>
    @get:Input abstract val policy: Property<String>
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val inputManifest: RegularFileProperty
    @get:org.gradle.api.tasks.Optional @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val resourceSymbols: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val lineageSeed: RegularFileProperty
    @get:Internal abstract val ownership: Property<HardeningOwnership>
    @get:Internal abstract val repositoryRoot: DirectoryProperty
    @get:OutputFile abstract val outputJar: RegularFileProperty
    @get:OutputFile abstract val closure: RegularFileProperty
    @get:OutputFile abstract val keepRules: RegularFileProperty
    @get:OutputFile abstract val report: RegularFileProperty
    @get:OutputDirectory abstract val generatedDirectory: DirectoryProperty

    init { variantName.convention(name) }

    @TaskAction fun protect() {
        val configuration = RuntimeProtectionPolicy.decode(policy.get())
        require(!configuration.images.enabled || minimumSdk.get() >= 26) { "runtime image protection requires minSdk 26 or newer" }
        val seed = lineageSeed.get().asFile.readBytes()
        val key = RuntimeEnvelope.key(seed)
        val helper = RuntimeEnvelope.helper(seed)
        seed.fill(0)
        val root = repositoryRoot.get().asFile.toPath().toAbsolutePath().normalize()
        val inputs = com.holin.android.hardening.runtime.RuntimeReaderInputs.read(inputJars.get().map { it.asFile },
            inputDirectories.get().map { it.asFile }, bootClasspath.files, sourceInputs.files, root, namespace.get(), resourceSymbols.orNull?.asFile)
        val entries = inputs.entries.toSortedMap()
        require("$helper.class" !in entries) { "runtime helper collides with a program class" }
        val owned = OwnedDexInventoryBuilder(root, ownership.get()).sourceInventory().mapTo(linkedSetOf()) {
            it.originalDescriptor.removePrefix("L").removeSuffix(";")
        }
        val xml = inputs.xml
        val analysis = RuntimeBytecodeAdapter.analyze(inputs.classes, inputs.hierarchy, owned, namespace.get(), xml, configuration)
        val context = mapOf("variant" to variantName.get(), "inputFingerprint" to
            com.holin.android.hardening.runtime.RuntimeStringDiagnostics.fingerprint(configuration, namespace.get(), inputs.classes, inputs.hierarchy, xml),
            "productionSourceFilesModified" to false)
        val readerReport = analysis.report + context + mapOf("status" to analysis.stringReport.getValue("status"))
        report.get().asFile.apply { parentFile.mkdirs(); writeText(JsonOutput.prettyPrint(JsonOutput.toJson(readerReport))) }
        analysis.requireStrings(report.get().asFile.path)
        analysis.requireAssets()
        val skipped = configuration.candidateStrings - analysis.stringNames
        if (skipped.isNotEmpty()) logger.warn("{} candidate runtime strings have unsupported readers; report: {}", skipped.size, report.get().asFile)
        val adapted = RuntimeBytecodeAdapter.apply(inputs.classes, analysis, helper)
        val assetHashes = linkedMapOf<String, String>()
        val assetSkips = linkedMapOf<String, String>()
        if (adapted.assetsClosed) configuration.assetPaths.sorted().forEach { path ->
            if (path.substringAfterLast('.').lowercase() in setOf("pem", "cer", "crt", "der", "p12", "bks", "jks", "keystore")) {
                assetSkips[path] = "CERTIFICATE_OR_KEYSTORE_CONTRACT"
                return@forEach
            }
            val candidates = ownership.get().modules.flatMap { module -> module.sourceRoots.assetDirectories.map { it.resolve(path) } }
                .filter { Files.isRegularFile(it) && !Files.isSymbolicLink(it) }
            val ignored = com.holin.android.hardening.inventory.GitIgnoreMatcher(root).ignored(candidates)
            val hashes = candidates.filterNot { it in ignored }.map(Sha256::file).distinct()
            if (hashes.size == 1) assetHashes[path] = hashes.single()
            else assetSkips[path] = "SOURCE_MISSING_IGNORED_OR_AMBIGUOUS"
        }
        val assetCoverage = if (configuration.assetPaths.isEmpty()) 0.0 else assetHashes.size.toDouble() / configuration.assetPaths.size
        require(assetCoverage >= configuration.minimumAssetCoverage) { "owned runtime asset coverage $assetCoverage is below ${configuration.minimumAssetCoverage}: $assetSkips" }
        val imageNames = sourceInputs.files.asSequence().filter { it.isFile &&
            it.parentFile.name.substringBefore('-') == "drawable" && it.extension.lowercase() in setOf("png", "webp") }
            .map { it.name.substringBefore('.') }.filter(configuration.images::accepts).toSet()
        val imageAudit = com.holin.android.hardening.runtime.RuntimeImageReferences.audit(adapted.classes, namespace.get(), imageNames, xml)
        val closedImages = imageAudit.filterValues { it.isEmpty() }.keys
        val active = adapted.stringNames.isNotEmpty() || assetHashes.isNotEmpty() || closedImages.isNotEmpty()
        adapted.classes.forEach { (name, bytes) -> entries["$name.class"] = bytes }
        if (assetHashes.isNotEmpty()) {
            val factory = javax.xml.parsers.DocumentBuilderFactory.newInstance()
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            factory.isNamespaceAware = true
            val manifest = factory.newDocumentBuilder().parse(inputManifest.get().asFile)
            val application = manifest.getElementsByTagName("application").item(0) as org.w3c.dom.Element
            val declared = application.getAttributeNS("http://schemas.android.com/apk/res/android", "name")
            val applicationClass = (when {
                declared.startsWith('.') -> namespace.get() + declared
                '.' !in declared -> namespace.get() + "." + declared
                else -> declared
            }).replace('.', '/')
            val applicationPath = "$applicationClass.class"
            val original = requireNotNull(entries[applicationPath]) {
                "Runtime assets require an instrumentable Application class for descriptor compatibility: $declared"
            }
            entries[applicationPath] = com.holin.android.hardening.runtime.RuntimeApplicationBootstrap.install(original, helper)
        }
        if (active) {
            val template = requireNotNull(javaClass.classLoader.getResourceAsStream("com/holin/android/hardening/runtime/Bridge.java.template")).use { it.readBytes().toString(Charsets.UTF_8) }
            val javaSource = template.replace("@PACKAGE@", helper.substringBeforeLast('/').replace('/', '.'))
                .replace("@KEY@", Base64.getEncoder().encodeToString(key)).replace("@PREFIX@", RuntimeEnvelope.prefix(key))
                .replace("@ASSETS@", assetHashes.keys.joinToString(",") { "\"${RuntimeEnvelope.pathKey(it, key)}\"" })
                .replace("@ASSET_NAMES@", assetHashes.keys.joinToString(",") { "\"${RuntimeEnvelope.encodeString(it, key, "asset-name:$it")}\"" })
                .replace("@IMAGES@", if (closedImages.isEmpty()) "" else requireNotNull(javaClass.classLoader.getResourceAsStream(
                    "com/holin/android/hardening/runtime/Image.java.template")).use { it.readBytes().toString(Charsets.UTF_8) })
            val directory = generatedDirectory.get().asFile
            directory.deleteRecursively()
            val source = directory.resolve("src/$helper.java").apply { parentFile.mkdirs(); writeText(javaSource) }
            val classes = directory.resolve("classes").apply { mkdirs() }
            val compiler = requireNotNull(ToolProvider.getSystemJavaCompiler()) { "runtime adapters require the Gradle JDK compiler" }
            val errors = java.io.ByteArrayOutputStream()
            val code = compiler.run(null, errors, errors, "-source", "8", "-target", "8", "-encoding", "UTF-8", "-g", "-classpath",
                bootClasspath.asPath, "-d", classes.path, source.path)
            require(code == 0) { "runtime helper compilation failed: ${errors.toString(Charsets.UTF_8)}" }
            classes.walkTopDown().filter { it.isFile && it.extension == "class" }.forEach { file ->
                entries[file.relativeTo(classes).invariantSeparatorsPath] = file.readBytes()
            }
        } else generatedDirectory.get().asFile.mkdirs()
        val output = outputJar.get().asFile.apply { parentFile.mkdirs() }
        ZipOutputStream(output.outputStream().buffered()).use { zip -> entries.forEach { (name, bytes) ->
            zip.putNextEntry(ZipEntry(name).apply { time = 0 }); zip.write(bytes); zip.closeEntry()
        } }
        closure.get().asFile.apply { parentFile.mkdirs(); writeText(JsonOutput.toJson(mapOf("schemaVersion" to 1,
            "policy" to configuration.encode(), "strings" to adapted.stringNames.sorted(), "assets" to assetHashes,
            "images" to closedImages.sorted(), "stringAnalysis" to analysis.stringReport, "helper" to if (active) helper else "", "classJarSha256" to Sha256.file(output.toPath())))) }
        keepRules.get().asFile.apply { parentFile.mkdirs(); writeText(if (active) "-keep class ${helper.replace('/', '.')} { *; }\n-keep class ${helper.replace('/', '.')}\$* { *; }\n" else "# No closed runtime readers.\n") }
        report.get().asFile.apply { parentFile.mkdirs(); writeText(JsonOutput.prettyPrint(JsonOutput.toJson(adapted.report + context + mapOf("ownedAssetHashes" to assetHashes, "assetCoverage" to assetCoverage, "assetSkips" to assetSkips,
            "images" to imageAudit.map { (name, reasons) -> mapOf("name" to name, "closed" to reasons.isEmpty(), "reasons" to reasons.sorted()) },
            "helper" to if (active) helper else "", "productionSourceFilesModified" to false)))) }
        key.fill(0)
    }
}
