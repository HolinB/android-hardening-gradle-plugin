package com.holin.android.hardening.tasks

import com.holin.android.hardening.artifact.ArtifactPathBoundary
import com.holin.android.hardening.similarity.FullAabSimilarityReportCodec
import com.holin.android.hardening.similarity.FullAabStructuralAnalyzer
import com.holin.android.hardening.similarity.FullAabStructuralSimilarityScorerV1
import com.holin.android.hardening.state.AtomicFiles
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.work.DisableCachingByDefault

@DisableCachingByDefault(
    because = "External AAB comparison is an explicit local report operation",
)
abstract class CompareExternalHardeningAabTask : DefaultTask() {
    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val referenceAab: RegularFileProperty
    @get:InputFile @get:Optional @get:PathSensitive(PathSensitivity.NONE)
    abstract val candidateAab: RegularFileProperty
    @get:OutputFile abstract val jsonReport: RegularFileProperty
    @get:OutputFile abstract val markdownReport: RegularFileProperty
    @get:Internal abstract val artifactBoundary: DirectoryProperty

    init {
        outputs.upToDateWhen { false }
    }

    @TaskAction
    fun compare() {
        val reference = referenceAab.orNull?.asFile?.toPath()?.toAbsolutePath()?.normalize()
            ?: throw IllegalArgumentException(
                "Missing -PandroidHardeningReferenceAab=/absolute/path/reference.aab for $name",
            )
        require(Files.isRegularFile(reference, NOFOLLOW_LINKS) && !Files.isSymbolicLink(reference)) {
            "androidHardeningReferenceAab is not a non-symlink regular file: $reference"
        }
        val boundary = ArtifactPathBoundary(artifactBoundary.get().asFile.toPath())
        val candidate = candidateAab.orNull?.asFile?.toPath()?.let(boundary::requireInput)
            ?: throw IllegalArgumentException("verified hardened candidate AAB is missing for $name")
        val analyzer = FullAabStructuralAnalyzer()
        val report = FullAabStructuralSimilarityScorerV1.compare(
            analyzer.analyze(reference),
            analyzer.analyze(candidate),
        )
        val atomic = AtomicFiles()
        atomic.replace(
            boundary.prepareOutput(jsonReport.get().asFile.toPath()),
            FullAabSimilarityReportCodec.encode(report).toByteArray(Charsets.UTF_8),
        )
        atomic.replace(
            boundary.prepareOutput(markdownReport.get().asFile.toPath()),
            FullAabSimilarityReportCodec.encodeMarkdown(report).toByteArray(Charsets.UTF_8),
        )
    }
}
