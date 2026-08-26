package com.holin.android.hardening.similarity

import kotlin.test.Test
import kotlin.test.assertEquals

class BaselineOwnedDescriptorAlignerTest {
    @Test
    fun `aligns common owned classes across lineages and rejects mixed baseline outputs`() {
        val baselineMapping = """
            com.example.First -> old.pkg.A:
            com.example.Second -> old.pkg.B:
            com.external.Dependency -> old.pkg.B:
            com.example.Removed -> old.pkg.C:
        """.trimIndent()
        val currentMapping = """
            com.example.First -> new.pkg.A:
            com.example.Second -> new.pkg.B:
            com.example.Added -> new.pkg.C:
        """.trimIndent()

        val alignment = BaselineOwnedDescriptorAligner().align(
            baselineMapping,
            currentMapping,
            setOf("Lnew/pkg/A;", "Lnew/pkg/B;", "Lnew/pkg/C;"),
        )

        assertEquals(setOf("Lold/pkg/A;"), alignment.baselineDescriptors)
        assertEquals(setOf("Lnew/pkg/A;"), alignment.currentDescriptors)
        assertEquals(1, alignment.commonOriginalDescriptorCount)
        assertEquals(2, alignment.currentOnlyOrMixedOriginalDescriptorCount)
    }

    @Test
    fun `retains merged baseline output when every contributor is owned`() {
        val baselineMapping = """
            com.example.First -> old.pkg.A:
            com.example.Second -> old.pkg.A:
        """.trimIndent()
        val currentMapping = """
            com.example.First -> new.pkg.A:
            com.example.Second -> new.pkg.B:
        """.trimIndent()

        val alignment = BaselineOwnedDescriptorAligner().align(
            baselineMapping,
            currentMapping,
            setOf("Lnew/pkg/A;", "Lnew/pkg/B;"),
        )

        assertEquals(setOf("Lold/pkg/A;"), alignment.baselineDescriptors)
        assertEquals(setOf("Lnew/pkg/A;", "Lnew/pkg/B;"), alignment.currentDescriptors)
        assertEquals(2, alignment.commonOriginalDescriptorCount)
        assertEquals(0, alignment.currentOnlyOrMixedOriginalDescriptorCount)
    }

    @Test
    fun `rejects a current output merged from baseline common and current only originals`() {
        val baselineMapping = """
            com.example.First -> old.pkg.A:
            com.example.Safe -> old.pkg.B:
        """.trimIndent()
        val currentMapping = """
            com.example.First -> new.pkg.A:
            com.example.Added -> new.pkg.A:
            com.example.Safe -> new.pkg.B:
        """.trimIndent()

        val alignment = BaselineOwnedDescriptorAligner().align(
            baselineMapping,
            currentMapping,
            setOf("Lnew/pkg/A;", "Lnew/pkg/B;"),
        )

        assertEquals(setOf("Lold/pkg/B;"), alignment.baselineDescriptors)
        assertEquals(setOf("Lnew/pkg/B;"), alignment.currentDescriptors)
        assertEquals(1, alignment.commonOriginalDescriptorCount)
        assertEquals(2, alignment.currentOnlyOrMixedOriginalDescriptorCount)
    }
}
