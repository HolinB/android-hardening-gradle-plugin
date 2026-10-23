package com.holin.android.hardening.tasks

import com.holin.android.hardening.runtime.RuntimeBytecodeAdapter
import com.holin.android.hardening.runtime.RuntimeProtectionPolicy
import com.holin.android.hardening.runtime.RuntimeReaderInputs
import com.holin.android.hardening.runtime.RuntimeStringDiagnostics
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

@DisableCachingByDefault
abstract class CheckHardeningRuntimeStringsTask : DefaultTask() {
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val inputJars: ListProperty<RegularFile>
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val inputDirectories: ListProperty<Directory>
    @get:InputFiles @get:PathSensitive(PathSensitivity.NONE) abstract val bootClasspath: ConfigurableFileCollection
    @get:InputFiles @get:PathSensitive(PathSensitivity.RELATIVE) abstract val sourceInputs: ConfigurableFileCollection
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val resourceSymbols: RegularFileProperty
    @get:Input abstract val sourceOwnership: ListProperty<String>
    @get:Input abstract val namespace: Property<String>
    @get:Input abstract val variantName: Property<String>
    @get:Input abstract val policy: Property<String>
    @get:Internal abstract val repositoryRoot: DirectoryProperty
    @get:OutputFile abstract val report: RegularFileProperty

    @TaskAction fun checkStrings() {
        val configuration = RuntimeProtectionPolicy.decode(policy.get())
        val inputs = RuntimeReaderInputs.read(inputJars.get().map { it.asFile }, inputDirectories.get().map { it.asFile },
            bootClasspath.files, sourceInputs.files, repositoryRoot.get().asFile.toPath().toAbsolutePath().normalize(), namespace.get(), resourceSymbols.get().asFile)
        val analysis = RuntimeBytecodeAdapter.analyze(inputs.classes, inputs.hierarchy, emptySet(), namespace.get(), inputs.xml, configuration)
        @Suppress("UNCHECKED_CAST")
        val entries = (analysis.stringReport.getValue("entries") as List<Map<String, Any>>).map { it + mapOf("stage" to "PREFLIGHT") }
        val diagnostic = analysis.stringReport + mapOf("entries" to entries) + mapOf("stage" to "PREFLIGHT", "variant" to variantName.get(),
            "inputFingerprint" to RuntimeStringDiagnostics.fingerprint(configuration, namespace.get(), inputs.classes, inputs.hierarchy, inputs.xml),
            "productionSourceFilesModified" to false, "finalResourceChecksPending" to true,
            "textViewMetadataDifference" to analysis.report.getValue("textViewMetadataDifference"))
        val output = report.get().asFile
        output.parentFile.mkdirs()
        output.writeText(JsonOutput.prettyPrint(JsonOutput.toJson(diagnostic)))
        RuntimeStringDiagnostics.requireCoverage(configuration, analysis.stringNames, diagnostic, output.path)
        val skipped = configuration.candidateStrings - analysis.stringNames
        if (skipped.isNotEmpty()) logger.warn("{} candidate runtime strings have unsupported readers; report: {}", skipped.size, output)
        logger.lifecycle("Runtime string preflight completed; final resource checks remain pending. Report: {}", output)
    }
}
