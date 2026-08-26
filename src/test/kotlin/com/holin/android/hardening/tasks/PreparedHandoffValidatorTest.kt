package com.holin.android.hardening.tasks

import com.holin.android.hardening.state.ArchiveRequest
import com.holin.android.hardening.state.PrepareRequest
import com.holin.android.hardening.state.StateCoordinates
import com.holin.android.hardening.state.StateStore
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import org.junit.jupiter.api.io.TempDir

class PreparedHandoffValidatorTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `redirected root and prepared directory are rejected before archive writes`() {
        val root = temporary.resolve("configured-state/demo/demoRelease")
        val preparedDirectory = temporary.resolve("configured-prepared")
        val coordinates = StateCoordinates(
            "demo",
            "demoRelease",
            "com.example",
            "com.example.app",
            "b".repeat(64),
        )
        val prepared = StateStore().prepare(
            PrepareRequest(root, coordinates, preparedDirectory, "c".repeat(64), true, true, true),
        )
        val outsideRoot = temporary.resolve("outside-state")
        val outsidePrepared = temporary.resolve("outside-prepared")

        val rootFailure = assertFailsWith<IllegalArgumentException> {
            PreparedHandoffValidator.validate(prepared.copy(root = outsideRoot), root, preparedDirectory, coordinates)
        }
        val directoryFailure = assertFailsWith<IllegalArgumentException> {
            PreparedHandoffValidator.validate(
                prepared.copy(preparedDirectory = outsidePrepared),
                root,
                preparedDirectory,
                coordinates,
            )
        }

        assertContains(rootFailure.message!!, "root does not match")
        assertContains(directoryFailure.message!!, "directory does not match")
        assertFalse(outsideRoot.resolve("history").toFile().exists())
    }
}
