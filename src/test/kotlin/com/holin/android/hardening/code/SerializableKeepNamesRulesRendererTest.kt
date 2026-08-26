package com.holin.android.hardening.code

import com.holin.android.hardening.naming.RegistrySnapshot
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SerializableKeepNamesRulesRendererTest {
    @Test
    fun `renderer emits one sorted rule for each Serializable class exclusion`() {
        val alpha = "com/example/Alpha"
        val beta = "com/example/Beta"
        val plan = plan(
            exclusions = listOf(
                exclusion(CodeSymbolKind.CLASS, beta, "Beta", "L$beta;", CodeExclusionReason.SERIALIZABLE, "second"),
                exclusion(CodeSymbolKind.FIELD, alpha, "value", "I", CodeExclusionReason.SERIALIZABLE, "field"),
                exclusion(CodeSymbolKind.CLASS, alpha, "Alpha", "L$alpha;", CodeExclusionReason.SERIALIZABLE, "first"),
                exclusion(CodeSymbolKind.METHOD, alpha, "save", "()V", CodeExclusionReason.SERIALIZABLE, "method"),
                exclusion(CodeSymbolKind.CLASS, beta, "Beta", "L$beta;", CodeExclusionReason.SERIALIZABLE, "duplicate"),
                exclusion(CodeSymbolKind.CLASS, "com/example/Other", "Other", "Lcom/example/Other;", CodeExclusionReason.EXPORTED_COMPONENT, "other"),
            ),
            owners = setOf(alpha, beta, "com/example/Other"),
        )

        assertEquals(
            """
            -keepnames class com.example.Alpha
            -keepnames class com.example.Beta

            """.trimIndent(),
            SerializableKeepNamesRulesRenderer().render(plan),
        )
    }

    @Test
    fun `renderer rejects malformed Serializable class owners`() {
        val malformedOwner = "com.example.Broken"
        val plan = plan(
            exclusions = listOf(
                exclusion(
                    CodeSymbolKind.CLASS,
                    malformedOwner,
                    malformedOwner,
                    "L$malformedOwner;",
                    CodeExclusionReason.SERIALIZABLE,
                    "malformed",
                ),
            ),
            owners = setOf(malformedOwner),
        )

        assertFailsWith<IllegalArgumentException> { SerializableKeepNamesRulesRenderer().render(plan) }
    }

    @Test
    fun `renderer rejects Serializable class exclusions outside the owned plan`() {
        val owner = "com/example/NotOwned"
        val plan = plan(
            exclusions = listOf(
                exclusion(
                    CodeSymbolKind.CLASS,
                    owner,
                    "NotOwned",
                    "L$owner;",
                    CodeExclusionReason.SERIALIZABLE,
                    "non-owned",
                ),
            ),
            owners = emptySet(),
        )

        assertFailsWith<IllegalArgumentException> { SerializableKeepNamesRulesRenderer().render(plan) }
    }

    private fun exclusion(
        kind: CodeSymbolKind,
        owner: String,
        name: String,
        descriptor: String,
        reason: CodeExclusionReason,
        evidence: String,
    ) = CodeExclusion(CodeSymbolKey(kind, owner, name, descriptor), reason, evidence)

    private fun plan(exclusions: Collection<CodeExclusion>, owners: Collection<String>): CodeNamePlan {
        val constructor = Class.forName("com.holin.android.hardening.code.ImmutableCodeNamePlan").getDeclaredConstructor(
            Collection::class.java,
            Collection::class.java,
            RegistrySnapshot::class.java,
            Collection::class.java,
        )
        constructor.isAccessible = true
        return constructor.newInstance(emptyList<AssignedCodeName>(), exclusions, emptyRegistry(), owners) as CodeNamePlan
    }

    private fun emptyRegistry() = RegistrySnapshot(1, "0".repeat(64), 1, emptyList(), emptyList())
}
