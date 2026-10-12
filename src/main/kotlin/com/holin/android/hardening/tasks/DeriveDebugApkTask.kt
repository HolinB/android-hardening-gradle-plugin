package com.holin.android.hardening.tasks

import com.holin.android.hardening.artifact.DebugApkDerivative
import com.holin.android.hardening.artifact.SigningMaterial
import org.gradle.api.DefaultTask
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault

@DisableCachingByDefault
abstract class DeriveDebugApkTask : DefaultTask() {
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val sourceApk: RegularFileProperty
    @get:InputFile @get:PathSensitive(PathSensitivity.NONE) abstract val zipalignExecutable: RegularFileProperty
    @get:OutputFile abstract val debugApk: RegularFileProperty
    @get:OutputFile abstract val verificationReport: RegularFileProperty
    private lateinit var signingMaterial: SigningMaterial

    init {
        outputs.upToDateWhen { false }
        notCompatibleWithConfigurationCache("signing credentials must remain invocation-local")
    }

    internal fun useSigningMaterial(material: SigningMaterial) { signingMaterial = material }

    @TaskAction fun derive() = DebugApkDerivative.derive(
        sourceApk.get().asFile.toPath(), debugApk.get().asFile.toPath(),
        verificationReport.get().asFile.toPath(), zipalignExecutable.get().asFile.toPath(), signingMaterial,
    )
}
