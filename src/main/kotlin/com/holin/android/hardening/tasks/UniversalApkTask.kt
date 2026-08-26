package com.holin.android.hardening.tasks

import com.holin.android.hardening.artifact.ArtifactPathBoundary
import com.holin.android.hardening.artifact.BundleVerificationReportCodec
import com.holin.android.hardening.artifact.BundleRewriteManifestCodec
import com.holin.android.hardening.artifact.BundletoolUniversalApksBuilder
import com.holin.android.hardening.artifact.SigningMaterial
import com.holin.android.hardening.artifact.UniversalApksBuilder
import com.holin.android.hardening.artifact.UniversalApkAssembler
import com.holin.android.hardening.artifact.UniversalApkAssemblyRequest
import com.holin.android.hardening.artifact.OrdinaryUniversalApkAssembler
import com.holin.android.hardening.artifact.OrdinaryUniversalApkAssemblyRequest
import com.holin.android.hardening.state.HardeningStateLockService
import com.holin.android.hardening.state.InvocationSaltService
import java.nio.file.Files
import java.nio.file.Path
import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Classpath
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault
import org.gradle.workers.WorkAction
import org.gradle.workers.WorkParameters
import org.gradle.workers.WorkerExecutor

internal val BUNDLETOOL_WORKER_RUNTIME_COORDINATES = listOf(
    "com.android.tools.build:bundletool:1.18.1",
    "com.android.tools.build:aapt2-proto:8.13.2-14304508",
    "com.google.auto.value:auto-value-annotations:1.6.2",
    "com.google.code.findbugs:jsr305:3.0.2",
    "com.google.code.gson:gson:2.8.9",
    "com.google.dagger:dagger:2.28.3",
    "com.google.errorprone:error_prone_annotations:2.18.0",
    "com.google.guava:failureaccess:1.0.1",
    "com.google.guava:guava:32.0.1-jre",
    "com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava",
    "com.google.j2objc:j2objc-annotations:2.8",
    "com.google.protobuf:protobuf-java-util:3.22.3",
    "com.google.protobuf:protobuf-java:3.25.5",
    "javax.inject:javax.inject:1",
    "org.bitbucket.b_c:jose4j:0.9.5",
    "org.checkerframework:checker-qual:3.33.0",
    "org.slf4j:slf4j-api:1.7.30",
)

internal interface BundletoolBuildApksParameters : WorkParameters {
    val bundle: Property<String>
    val outputArchive: Property<String>
    val aapt2Executable: Property<String>
    val signingStore: Property<String>
    val signingStorePassword: Property<String>
    val signingKeyAlias: Property<String>
    val signingKeyPassword: Property<String>
    val signingStoreType: Property<String>
}

internal abstract class BundletoolBuildApksWorkAction : WorkAction<BundletoolBuildApksParameters> {
    override fun execute() {
        val values = parameters
        BundletoolUniversalApksBuilder().build(
            Path.of(values.bundle.get()),
            Path.of(values.outputArchive.get()),
            Path.of(values.aapt2Executable.get()),
            SigningMaterial.create(
                "bundletool-worker",
                Path.of(values.signingStore.get()),
                values.signingStorePassword.get(),
                values.signingKeyAlias.get(),
                values.signingKeyPassword.get(),
                values.signingStoreType.get(),
            ),
        )
    }
}

private class ProcessIsolatedBundletoolBuilder(
    private val workerExecutor: WorkerExecutor,
    private val workerClasspath: ConfigurableFileCollection,
) : UniversalApksBuilder {
    override fun build(
        bundle: Path,
        outputArchive: Path,
        aapt2Executable: Path,
        signingMaterial: SigningMaterial,
    ) {
        val bundlePath = bundle
        val outputArchivePath = outputArchive
        val aapt2Path = aapt2Executable
        val queue = workerExecutor.processIsolation {
            classpath.from(workerClasspath)
        }
        queue.submit(BundletoolBuildApksWorkAction::class.java) {
            this.bundle.set(bundlePath.toString())
            this.outputArchive.set(outputArchivePath.toString())
            this.aapt2Executable.set(aapt2Path.toString())
            signingStore.set(signingMaterial.storeFile.toString())
            signingStorePassword.set(signingMaterial.storePassword)
            signingKeyAlias.set(signingMaterial.keyAlias)
            signingKeyPassword.set(signingMaterial.keyPassword)
            signingStoreType.set(signingMaterial.storeType)
        }
        queue.await()
    }
}

@DisableCachingByDefault(because = "The universal APK is signed from an invocation-specific verified hardened AAB")
abstract class AssembleHardeningUniversalApkTask : DefaultTask() {
    @get:Classpath
    abstract val bundletoolWorkerClasspath: ConfigurableFileCollection

    @get:Inject
    abstract val workerExecutor: WorkerExecutor

    @get:Input
    abstract val variantName: Property<String>

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val hardenedBundle: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val bundleVerificationReport: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val rewriteManifest: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val aapt2Executable: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val zipalignExecutable: RegularFileProperty

    @get:OutputFile
    abstract val universalApk: RegularFileProperty

    @get:OutputFile
    abstract val universalApkVerificationReport: RegularFileProperty

    @get:Internal
    abstract val artifactBoundary: DirectoryProperty

    @get:Internal
    abstract val lockService: Property<HardeningStateLockService>

    @get:Internal
    abstract val saltService: Property<InvocationSaltService>

    private lateinit var signingMaterial: SigningMaterial

    init {
        outputs.upToDateWhen { false }
        notCompatibleWithConfigurationCache("hardening signing credentials must remain invocation-local")
    }

    internal fun useSigningMaterial(material: SigningMaterial) {
        check(!::signingMaterial.isInitialized) { "hardening signing material was configured twice" }
        signingMaterial = material
    }

    @TaskAction
    fun assemble() {
        check(::signingMaterial.isInitialized) { "hardening signing material was not configured" }
        lockService.get().withLock {
            val paths = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
            val bundle = paths.requireInput(hardenedBundle.get().asFile.toPath())
            val bundleReportPath = paths.requireInput(bundleVerificationReport.get().asFile.toPath())
            val rewriteManifestPath = paths.requireInput(rewriteManifest.get().asFile.toPath())
            val aapt2 = aapt2Executable.get().asFile.toPath().toAbsolutePath().normalize()
            val zipalign = zipalignExecutable.get().asFile.toPath().toAbsolutePath().normalize()
            require(Files.isRegularFile(aapt2)) { "AGP AAPT2 executable is missing" }
            require(Files.isRegularFile(zipalign)) { "SDK zipalign executable is missing" }
            require(Files.size(bundleReportPath) in 1..MAX_BUNDLE_REPORT_BYTES) {
                "hardening bundle verification report has an invalid size"
            }
            val bundleReport = BundleVerificationReportCodec.decode(Files.readString(bundleReportPath))
            require(Files.size(rewriteManifestPath) in 1..MAX_REWRITE_MANIFEST_BYTES) {
                "hardening rewrite manifest has an invalid size"
            }
            val manifest = BundleRewriteManifestCodec.read(rewriteManifestPath)
            val outputApk = paths.prepareOutput(universalApk.get().asFile.toPath())
            val outputReport = paths.prepareOutput(universalApkVerificationReport.get().asFile.toPath())
            UniversalApkAssembler(
                ProcessIsolatedBundletoolBuilder(workerExecutor, bundletoolWorkerClasspath),
            ).assemble(
                UniversalApkAssemblyRequest(
                    variant = variantName.get(),
                    contentSaltSha256 = saltService.get().sha256(),
                    hardenedBundle = bundle,
                    aapt2Executable = aapt2,
                    zipalignExecutable = zipalign,
                    bundleVerification = bundleReport,
                    rewriteManifest = manifest,
                    targetApk = outputApk,
                    targetReport = outputReport,
                    signingMaterial = signingMaterial,
                ),
            )
            paths.requireInput(outputApk)
            paths.requireInput(outputReport)
        }
    }

    private companion object {
        const val MAX_BUNDLE_REPORT_BYTES = 16 * 1024L
        const val MAX_REWRITE_MANIFEST_BYTES = 16 * 1024 * 1024L
    }
}

@DisableCachingByDefault(because = "The ordinary universal APK is signed for explicit baseline/comparison tasks")
abstract class AssembleOrdinaryUniversalApkTask : DefaultTask() {
    @get:Classpath
    abstract val bundletoolWorkerClasspath: ConfigurableFileCollection

    @get:Inject
    abstract val workerExecutor: WorkerExecutor

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val ordinaryBundle: RegularFileProperty

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val aapt2Executable: RegularFileProperty

    @get:OutputFile
    abstract val universalApk: RegularFileProperty

    @get:Internal
    abstract val artifactBoundary: DirectoryProperty

    private lateinit var signingMaterial: SigningMaterial

    init {
        outputs.upToDateWhen { false }
        notCompatibleWithConfigurationCache("hardening signing credentials must remain invocation-local")
    }

    internal fun useSigningMaterial(material: SigningMaterial) {
        check(!::signingMaterial.isInitialized) { "ordinary universal APK signing material was configured twice" }
        signingMaterial = material
    }

    @TaskAction
    fun assemble() {
        check(::signingMaterial.isInitialized) { "ordinary universal APK signing material was not configured" }
        val paths = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
        val ordinary = paths.requireInput(ordinaryBundle.get().asFile.toPath())
        val aapt2 = aapt2Executable.get().asFile.toPath().toAbsolutePath().normalize()
        require(Files.isRegularFile(aapt2)) { "AGP AAPT2 executable is missing" }
        val output = paths.prepareOutput(universalApk.get().asFile.toPath())
        OrdinaryUniversalApkAssembler(
            ProcessIsolatedBundletoolBuilder(workerExecutor, bundletoolWorkerClasspath),
        ).assemble(
            OrdinaryUniversalApkAssemblyRequest(ordinary, aapt2, output, signingMaterial),
        )
        paths.requireInput(output)
    }
}
