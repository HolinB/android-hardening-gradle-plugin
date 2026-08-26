package com.holin.android.hardening.verification

import kotlin.test.Test
import kotlin.test.assertEquals

class MappingContinuityVerifierTest {
    @Test
    fun `registry expectation requires exact surviving R8 aliases`() {
        val expected = parse(
            """
            com.example.Owner -> amber.river.CalmHarbor:
                java.lang.Object binding -> gentleMeadow
            """.trimIndent(),
        )
        val current = parse(
            """
            com.example.Owner -> amber.river.CalmHarbor:
                java.lang.Object binding -> otherName
            """.trimIndent(),
        )

        val result = MappingContinuityVerifier().verify(expected, current)

        assertEquals(1, result.mismatches.size)
        assertEquals("binding", result.mismatches.single().key.originalName)
    }

    @Test
    fun `requires stable names only for symbols with the same JVM identity`() {
        val previous = parse(
            """
            com.example.Foo -> a:
                int value -> b
                1:1:void stable(java.lang.String):10:10 -> c
                2:2:void signatureChanged(java.lang.String):20:20 -> d
                3:3:void deleted():30:30 -> e
            com.example.Deleted -> x:
                1:1:void gone():40:40 -> y
            """.trimIndent(),
        )
        val current = parse(
            """
            com.example.Foo -> a:
                int value -> b
                1:1:void stable(java.lang.String):10:10 -> c
                2:2:void signatureChanged(int):20:20 -> z
            """.trimIndent(),
        )

        val result = MappingContinuityVerifier().verify(previous, current)

        assertEquals(3, result.applicableCount)
        assertEquals(3, result.stableCount)
        assertEquals(4, result.noLongerPresentCount)
        assertEquals(emptyList(), result.mismatches)
    }

    @Test
    fun `reports class field and method name drift deterministically`() {
        val previous = parse(
            """
            com.example.Foo -> a:
                int value -> b
                1:1:void run():10:10 -> c
            """.trimIndent(),
        )
        val current = parse(
            """
            com.example.Foo -> z:
                int value -> y
                1:1:void run():10:10 -> x
            """.trimIndent(),
        )

        val result = MappingContinuityVerifier().verify(previous, current)

        assertEquals(3, result.applicableCount)
        assertEquals(0, result.stableCount)
        assertEquals(listOf(SymbolKind.CLASS, SymbolKind.FIELD, SymbolKind.METHOD), result.mismatches.map { it.key.kind })
    }

    private fun parse(mapping: String): ParsedR8Mapping = R8MappingParser().parse(mapping, null)
}
