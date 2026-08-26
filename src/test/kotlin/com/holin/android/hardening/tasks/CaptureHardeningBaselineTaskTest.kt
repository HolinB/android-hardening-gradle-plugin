package com.holin.android.hardening.tasks

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.OutputDirectory
import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.io.TempDir

class CaptureHardeningBaselineTaskTest {
    @TempDir
    lateinit var repository: Path

    @Test
    fun `exact immutable baseline target is internal and only its derived parent is an output`() {
        val getters = CaptureHardeningBaselineTask::class.java.declaredMethods
            .filter { method -> method.name.startsWith("get") }
        val baselineRootGetter = getters.single { method -> method.name == "getBaselineRoot" }

        assertTrue(baselineRootGetter.isAnnotationPresent(Internal::class.java))
        assertFalse(baselineRootGetter.isAnnotationPresent(OutputDirectory::class.java))
        assertEquals(
            listOf("getBaselineParentDirectory"),
            getters.filter { method -> method.isAnnotationPresent(OutputDirectory::class.java) }
                .map { method -> method.name },
        )
    }

    @Test
    fun `Gradle output model contains immediate baseline parent but not immutable v1 target`() {
        val project = ProjectBuilder.builder().withProjectDir(repository.toFile()).build()
        val task = project.tasks.register("captureBaseline", CaptureHardeningBaselineTask::class.java).get()
        val baselineRoot = repository.resolve(".hardening/baselines/demo/demoDebug/v1")
            .toAbsolutePath()
            .normalize()
        task.baselineRoot.set(project.layout.dir(project.provider { baselineRoot.toFile() }))

        val outputPaths = task.outputs.files.files
            .mapTo(linkedSetOf()) { file -> file.toPath().toAbsolutePath().normalize() }

        assertEquals(setOf(baselineRoot.parent), outputPaths)
        assertFalse(baselineRoot in outputPaths)
    }

    @Test
    fun `rewrite capture and compare declare separate identity and analysis inventory files`() {
        val rewriteOutputs = RewriteHardeningBundleTask::class.java.declaredMethods
            .filter { method -> method.isAnnotationPresent(OutputFile::class.java) }
            .mapTo(linkedSetOf()) { method -> method.name }
        val captureInputs = CaptureHardeningBaselineTask::class.java.declaredMethods
            .filter { method -> method.isAnnotationPresent(InputFile::class.java) }
            .mapTo(linkedSetOf()) { method -> method.name }
        val compareInputs = CompareHardeningSimilarityTask::class.java.declaredMethods
            .filter { method -> method.isAnnotationPresent(InputFile::class.java) }
            .mapTo(linkedSetOf()) { method -> method.name }

        assertTrue("getOwnedArtifactInventory" in rewriteOutputs)
        assertTrue("getOwnedArtifactAnalysisInventory" in rewriteOutputs)
        assertTrue("getOwnedArtifactInventory" in captureInputs)
        assertTrue("getOwnedArtifactAnalysisInventory" in captureInputs)
        assertTrue("getOwnedArtifactInventory" in compareInputs)
        assertTrue("getOwnedArtifactAnalysisInventory" in compareInputs)
    }
}
