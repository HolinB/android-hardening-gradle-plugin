package com.holin.android.hardening.tasks

import com.holin.android.hardening.HardcodedReferenceKind
import com.holin.android.hardening.HardeningOwnership
import com.holin.android.hardening.audit.HardeningSourceAudit
import com.holin.android.hardening.audit.UnresolvedHardcodedReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HardcodedReferencePolicyTest {
    @Test
    fun `enabled fail policy blocks each scoped unresolved hardcoded category and disabled policy reports only`() {
        val findings = listOf(
            UnresolvedHardcodedReference(HardcodedReferenceKind.CLASS_NAME, "src/A.kt", 1, "Class.forName(remote)", "dynamic"),
            UnresolvedHardcodedReference(HardcodedReferenceKind.MEMBER_NAME, "src/A.kt", 2, "Model.getMethod(name, types)", "dynamic descriptor"),
            UnresolvedHardcodedReference(HardcodedReferenceKind.RESOURCE_NAME, "src/A.kt", 3, "resources.getIdentifier(name, type, pkg)", "dynamic"),
        )
        val audit = HardeningSourceAudit(
            emptyList(),
            emptyList(),
            emptyList(),
            emptyList(),
            emptyList(),
            emptyList(),
            emptyList(),
            findings,
        )
        val blockingScope = scope(true)
        val reportingScope = scope(false)

        val violations = hardcodedReferenceViolations(blockingScope, audit)

        assertEquals(3, violations.size)
        assertTrue(violations.all { it.contains("unresolved hardcoded reference") })
        assertTrue(hardcodedReferenceViolations(reportingScope, audit).isEmpty())
    }

    private fun scope(fail: Boolean): HardeningOwnership.HardcodedReferenceScope =
        HardeningOwnership.HardcodedReferenceScope.resolve(
            setOf(
                HardcodedReferenceKind.CLASS_NAME,
                HardcodedReferenceKind.MEMBER_NAME,
                HardcodedReferenceKind.RESOURCE_NAME,
            ),
            setOf("**/*.kt"),
            emptySet(),
            fail,
            true,
        )
}
