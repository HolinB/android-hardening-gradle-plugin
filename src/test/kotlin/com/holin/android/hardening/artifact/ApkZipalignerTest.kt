package com.holin.android.hardening.artifact

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class ApkZipalignerTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `align and post-sign check use exact wired executable and required arguments`() {
        val executable = temporary.resolve("sdk/build-tools/35.0.0/zipalign").also {
            Files.createDirectories(it.parent)
            Files.writeString(it, "fixture")
        }
        val input = temporary.resolve("unsigned.apk").also { Files.writeString(it, "apk") }
        val aligned = temporary.resolve("aligned.apk")
        val signed = temporary.resolve("signed.apk").also { Files.writeString(it, "signed") }
        val commands = mutableListOf<List<String>>()
        val aligner = ApkZipaligner(ApkZipalignCommandRunner { command ->
            commands += command
            if ("-f" in command) Files.copy(input, aligned)
            0
        })

        aligner.align(executable, input, aligned)
        aligner.verify(executable, signed)

        assertEquals(
            listOf(
                listOf(
                    executable.toString(), "-f", "-P", "16", "4", input.toString(), aligned.toString(),
                ),
                listOf(executable.toString(), "-c", "-P", "16", "4", signed.toString()),
            ),
            commands,
        )
        assertTrue(Files.isRegularFile(aligned))
    }

    @Test
    fun `nonzero alignment exit fails without output publication`() {
        val executable = temporary.resolve("zipalign").also { Files.writeString(it, "fixture") }
        val input = temporary.resolve("unsigned.apk").also { Files.writeString(it, "apk") }
        val aligned = temporary.resolve("must-not-exist.apk")

        val failure = assertFailsWith<IllegalStateException> {
            ApkZipaligner(ApkZipalignCommandRunner { 7 }).align(executable, input, aligned)
        }

        assertTrue(failure.message.orEmpty().contains("exit 7"))
        assertFalse(Files.exists(aligned))
    }
}
