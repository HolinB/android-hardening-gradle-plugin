package com.holin.android.hardening.code

import com.holin.android.hardening.naming.RegistrySnapshot
import kotlin.test.Test
import kotlin.test.assertEquals

class HardcodedMemberKeepNamesRulesRendererTest {
    @Test
    fun `renderer emits exact member name contracts without preserving unrelated same name members`() {
        val model = "com/example/Model"
        val unrelated = "com/example/Unrelated"
        val plan = plan(
            listOf(
                exclusion(model, CodeSymbolKind.FIELD, "token", "Ljava/lang/String;", CodeExclusionReason.HARDCODED_MEMBER_NAME),
                exclusion(model, CodeSymbolKind.METHOD, "render", "(Ljava/lang/String;)Ljava/lang/String;", CodeExclusionReason.HARDCODED_MEMBER_NAME),
                exclusion(unrelated, CodeSymbolKind.METHOD, "render", "(Ljava/lang/String;)Ljava/lang/String;", CodeExclusionReason.EXTERNAL_OVERRIDE),
            ),
            setOf(model, unrelated),
        )

        assertEquals(
            """
            -keepclassmembers,allowoptimization class com.example.Model {
                java.lang.String render(java.lang.String);
                java.lang.String token;
            }

            """.trimIndent(),
            HardcodedMemberKeepNamesRulesRenderer().render(plan),
        )
    }

    private fun exclusion(
        owner: String,
        kind: CodeSymbolKind,
        name: String,
        descriptor: String,
        reason: CodeExclusionReason,
    ) = CodeExclusion(CodeSymbolKey(kind, owner, name, descriptor), reason, "fixture")

    private fun plan(exclusions: Collection<CodeExclusion>, owners: Collection<String>): CodeNamePlan {
        val constructor = Class.forName("com.holin.android.hardening.code.ImmutableCodeNamePlan").getDeclaredConstructor(
            Collection::class.java,
            Collection::class.java,
            RegistrySnapshot::class.java,
            Collection::class.java,
        )
        constructor.isAccessible = true
        return constructor.newInstance(
            emptyList<AssignedCodeName>(),
            exclusions,
            RegistrySnapshot(1, "0".repeat(64), 1, emptyList(), emptyList()),
            owners,
        ) as CodeNamePlan
    }
}
