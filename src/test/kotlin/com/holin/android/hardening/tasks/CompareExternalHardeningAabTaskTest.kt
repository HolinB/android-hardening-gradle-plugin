package com.holin.android.hardening.tasks

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFailsWith
import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path

class CompareExternalHardeningAabTaskTest {
    @TempDir
    lateinit var projectDirectory: Path

    @Test
    fun `missing reference property fails before candidate analysis`() {
        val project = ProjectBuilder.builder().withProjectDir(projectDirectory.toFile()).build()
        val task = project.tasks.register(
            "compareExternalHardeningDemoRelease",
            CompareExternalHardeningAabTask::class.java,
        ).get().apply {
            artifactBoundary.set(project.layout.buildDirectory)
            jsonReport.set(project.layout.buildDirectory.file("reports/external.json"))
            markdownReport.set(project.layout.buildDirectory.file("reports/external.md"))
        }

        val failure = assertFailsWith<IllegalArgumentException> { task.compare() }

        assertContains(failure.message.orEmpty(), "-PandroidHardeningReferenceAab=/absolute/path/reference.aab")
    }
}
