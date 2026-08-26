package com.holin.android.hardening.code

import com.holin.android.hardening.naming.RegistrySnapshot
import com.holin.android.hardening.verification.MappingSymbolKey
import com.holin.android.hardening.verification.R8MappingParser
import com.holin.android.hardening.verification.SymbolKind
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class R8CodeMappingRendererTest {
    @Test
    fun `renderer emits exact parseable Java types for classes fields overloads arrays and primitives`() {
        val owner = "com/example/Owner"
        val plan = plan(
            AssignedCodeName(CodeSymbolKey(CodeSymbolKind.CLASS, owner, "Owner", "Lcom/example/Owner;"), "QuietMeadow", "renamed/QuietMeadow"),
            AssignedCodeName(CodeSymbolKey(CodeSymbolKind.FIELD, owner, "matrix", "[[I"), "calmHarbor", "renamed/QuietMeadow"),
            AssignedCodeName(CodeSymbolKey(CodeSymbolKind.METHOD, owner, "render", "(I[Ljava/lang/String;)V"), "gentleMeadow", "renamed/QuietMeadow"),
            AssignedCodeName(CodeSymbolKey(CodeSymbolKind.METHOD, owner, "render", "([[Z)Ljava/lang/Object;"), "tidalRiver", "renamed/QuietMeadow"),
        )

        val mapping = R8CodeMappingRenderer().render(plan)
        val parsed = R8MappingParser().parse(mapping, ownedOriginalDescriptors = null)

        assertEquals(
            """
            com.example.Owner -> renamed.QuietMeadow:
                int[][] matrix -> calmHarbor
                void render(int,java.lang.String[]) -> gentleMeadow
                java.lang.Object render(boolean[][]) -> tidalRiver

            """.trimIndent(),
            mapping,
        )
        assertEquals(
            setOf("tidalRiver"),
            parsed.symbols.getValue(MappingSymbolKey(SymbolKind.METHOD, "com.example.Owner", "render", "([[Z)Ljava/lang/Object;")),
        )
    }

    @Test
    fun `renderer emits a same owner header for eligible members of an excluded class`() {
        val owner = "com/example/Preserved"
        val plan = testCodeNamePlan(
            assignments = listOf(
                AssignedCodeName(CodeSymbolKey(CodeSymbolKind.METHOD, owner, "work", "()V"), "calmHarbor", owner),
            ),
            exclusions = listOf(
                CodeExclusion(
                    CodeSymbolKey(CodeSymbolKind.CLASS, owner, "Preserved", "Lcom/example/Preserved;"),
                    CodeExclusionReason.EXPORTED_COMPONENT,
                    "manifest",
                ),
            ),
            registry = emptyRegistry(),
            ownedOriginalOwners = setOf(owner),
        )

        val mapping = R8CodeMappingRenderer().render(plan)

        assertContains(mapping, "com.example.Preserved -> com.example.Preserved:")
        assertContains(mapping, "void work() -> calmHarbor")
    }

    @Test
    fun `renderer omits exclusions constructors and dependency evidence`() {
        val owner = "com/example/Owner"
        val plan = testCodeNamePlan(
            assignments = listOf(
                AssignedCodeName(CodeSymbolKey(CodeSymbolKind.CLASS, owner, "Owner", "Lcom/example/Owner;"), "QuietMeadow", "renamed/QuietMeadow"),
            ),
            exclusions = listOf(
                CodeExclusion(CodeSymbolKey(CodeSymbolKind.METHOD, owner, "<init>", "()V"), CodeExclusionReason.CONSTRUCTOR, "constructor"),
                CodeExclusion(CodeSymbolKey(CodeSymbolKind.METHOD, "third/Api", "run", "()V"), CodeExclusionReason.EXTERNAL_OVERRIDE, "dependency"),
            ),
            registry = emptyRegistry(),
            ownedOriginalOwners = setOf(owner),
        )

        val mapping = R8CodeMappingRenderer().render(plan)

        assertFalse(mapping.contains("<init>"))
        assertFalse(mapping.contains("third.party.Api"))
        R8MappingParser().parse(mapping, ownedOriginalDescriptors = null)
    }

    @Test
    fun `renderer rejects a dependency assignment in a publicly constructed plan`() {
        val owner = "com/example/Owner"
        val dependency = "third/party/Api"
        val plan = testCodeNamePlan(
            assignments = listOf(
                AssignedCodeName(
                    CodeSymbolKey(CodeSymbolKind.CLASS, owner, "Owner", "Lcom/example/Owner;"),
                    "QuietMeadow",
                    "renamed/QuietMeadow",
                ),
                AssignedCodeName(
                    CodeSymbolKey(CodeSymbolKind.CLASS, dependency, "Api", "Lthird/party/Api;"),
                    "GentleHarbor",
                    "renamed/GentleHarbor",
                ),
            ),
            exclusions = emptyList(),
            registry = emptyRegistry(),
            ownedOriginalOwners = setOf(owner),
        )

        assertFailsWith<IllegalArgumentException> { R8CodeMappingRenderer().render(plan) }
    }

    @Test
    fun `plan ownership implementation has no public construction path`() {
        assertTrue(java.lang.reflect.Modifier.isAbstract(CodeNamePlan::class.java.modifiers))
        assertTrue(CodeNamePlan::class.java.constructors.all { constructor -> constructor.isSynthetic })
        assertTrue(CodeNamePlan::class.java.methods.none { method -> method.returnType == CodeNamePlan::class.java })
        val implementation = Class.forName("com.holin.android.hardening.code.ImmutableCodeNamePlan")
        assertEquals(listOf(implementation), CodeNamePlan::class.java.permittedSubclasses.toList())
        assertFalse(java.lang.reflect.Modifier.isPublic(implementation.modifiers))
    }

    @Test
    fun `renderer rejects injected class output owners`() {
        val owner = "com/example/Owner"
        val plan = testCodeNamePlan(
            assignments = listOf(
                AssignedCodeName(
                    CodeSymbolKey(CodeSymbolKind.CLASS, owner, "Owner", "L$owner;"),
                    "SafeClass",
                    "renamed/Safe\nthird/party/Api",
                ),
            ),
            exclusions = emptyList(),
            registry = emptyRegistry(),
            ownedOriginalOwners = setOf(owner),
        )

        assertFailsWith<IllegalArgumentException> { R8CodeMappingRenderer().render(plan) }
    }

    @Test
    fun `renderer rejects injected member names and trailing descriptor payloads`() {
        val owner = "com/example/Owner"
        fun malicious(kind: CodeSymbolKind, name: String, descriptor: String) = testCodeNamePlan(
            assignments = listOf(AssignedCodeName(CodeSymbolKey(kind, owner, name, descriptor), "calmHarbor", owner)),
            exclusions = emptyList(),
            registry = emptyRegistry(),
            ownedOriginalOwners = setOf(owner),
        )

        assertFailsWith<IllegalArgumentException> {
            R8CodeMappingRenderer().render(malicious(CodeSymbolKind.FIELD, "safe\nthird.party.Api", "I"))
        }
        assertFailsWith<IllegalArgumentException> {
            R8CodeMappingRenderer().render(malicious(CodeSymbolKind.METHOD, "run bad", "()V"))
        }
        assertFailsWith<IllegalArgumentException> {
            R8CodeMappingRenderer().render(malicious(CodeSymbolKind.FIELD, "value", "Ipayload"))
        }
        assertFailsWith<IllegalArgumentException> {
            R8CodeMappingRenderer().render(malicious(CodeSymbolKind.METHOD, "run", "()Vpayload"))
        }
    }

    private fun plan(vararg assignments: AssignedCodeName) = testCodeNamePlan(
        assignments.toList(),
        emptyList(),
        emptyRegistry(),
        assignments.mapTo(linkedSetOf()) { it.key.owner },
    )

    private fun emptyRegistry() = RegistrySnapshot(1, "0".repeat(64), 1, emptyList(), emptyList())

    private fun testCodeNamePlan(
        assignments: Collection<AssignedCodeName>,
        exclusions: Collection<CodeExclusion>,
        registry: RegistrySnapshot,
        ownedOriginalOwners: Collection<String>,
    ): CodeNamePlan {
        val constructor = Class.forName("com.holin.android.hardening.code.ImmutableCodeNamePlan").getDeclaredConstructor(
            Collection::class.java,
            Collection::class.java,
            RegistrySnapshot::class.java,
            Collection::class.java,
        )
        constructor.isAccessible = true
        return constructor.newInstance(assignments, exclusions, registry, ownedOriginalOwners) as CodeNamePlan
    }
}
