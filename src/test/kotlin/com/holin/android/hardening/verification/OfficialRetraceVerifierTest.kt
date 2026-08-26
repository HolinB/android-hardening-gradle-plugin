package com.holin.android.hardening.verification

import java.nio.file.Path
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class OfficialRetraceVerifierTest {
    @TempDir
    lateinit var temporary: Path

    @Test
    fun `official R8 Retrace restores the original class method and line`() {
        val verifier = OfficialRetraceVerifier()
        val runtimeVersion = verifier.runtimeVersion()
        val mapping = """
            # compiler: R8
            # compiler_version: $runtimeVersion
            # {"id":"com.android.tools.r8.mapping","version":"2.2"}
            com.example.Source -> a.b:
            # {"id":"sourceFile","fileName":"Source.kt"}
                7:7:void calculate():42:42 -> c
        """.trimIndent() + "\n"
        val mappingPath = temporary.resolve("mapping.txt").also { it.writeText(mapping) }
        val candidate = R8MappingParser().parse(mapping, null).retraceCandidates.single()

        val result = verifier.verify(mappingPath, candidate, runtimeVersion)

        assertTrue(result.verified)
        assertEquals(runtimeVersion, result.r8Version)
        assertTrue(result.retracedFrames.any { it.contains("com.example.Source.calculate(Source.kt:42)") })
    }

    @Test
    fun `official R8 Retrace rejects a mapping from a different compiler version`() {
        val verifier = OfficialRetraceVerifier()
        val runtimeVersion = verifier.runtimeVersion()
        val mappingVersion = "0.0.0"
        val mapping = """
            # compiler: R8
            # compiler_version: $mappingVersion
            # {"id":"com.android.tools.r8.mapping","version":"2.2"}
            com.example.Source -> a.b:
            # {"id":"sourceFile","fileName":"Source.kt"}
                7:7:void calculate():42:42 -> c
        """.trimIndent() + "\n"
        val mappingPath = temporary.resolve("mapping-mismatch.txt").also { it.writeText(mapping) }
        val candidate = R8MappingParser().parse(mapping, null).retraceCandidates.single()

        val result = verifier.verify(mappingPath, candidate, mappingVersion)

        assertFalse(result.verified)
        assertEquals(runtimeVersion, result.r8Version)
        assertEquals(emptyList(), result.retracedFrames)
        assertEquals(
            listOf(
                "official R8 Retrace version $runtimeVersion differs from mapping compiler version $mappingVersion",
            ),
            result.diagnostics,
        )
    }

    @Test
    fun `mapping without a line candidate fails closed`() {
        val mapping = "com.example.Source -> a:\n    void calculate() -> b\n"
        val parsed = R8MappingParser().parse(mapping, null)

        assertFailsWith<IllegalArgumentException> {
            OfficialRetraceVerifier().selectCandidate(parsed)
        }
    }
}
