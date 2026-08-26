package com.holin.android.hardening.similarity

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FullAabStructuralSimilarityScorerV1Test {
    @Test
    fun `renamed methods with identical canonical structure remain matches without ownership claims`() {
        val report = FullAabStructuralSimilarityScorerV1.compare(
            profile(
                "1".repeat(64),
                listOf(method("Lbefore/Alpha;->first()V", 120, "a")),
                listOf(resource("base/res/layout/screen.xml", 100, "c")),
            ),
            profile(
                "2".repeat(64),
                listOf(method("Lafter/Beta;->second()V", 120, "a")),
                listOf(resource("base/res/layout/screen.xml", 100, "c")),
            ),
        )

        assertEquals(100.0, report.dimensions.getValue(SimilarityDimension.CODE_METHODS))
        assertEquals(100.0, report.dimensions.getValue(SimilarityDimension.LONG_METHODS))
        assertEquals(FullAabComparisonScope.FULL_AAB, report.scope)
        assertFalse(report.ownershipVerified)
        assertEquals("Lafter/Beta;->second()V", report.topUnchangedCode.single().candidateDescriptor)
    }

    @Test
    fun `structural method and resource changes lower only their corresponding indexed dimensions`() {
        val report = FullAabStructuralSimilarityScorerV1.compare(
            profile(
                "1".repeat(64),
                listOf(
                    method("Lbefore/A;->a()V", 120, "a"),
                    method("Lbefore/B;->b()V", 60, "b"),
                ),
                listOf(
                    resource("base/res/layout/first.xml", 100, "c"),
                    resource("base/res/drawable/second.png", 300, "d"),
                ),
            ),
            profile(
                "2".repeat(64),
                listOf(
                    method("Lafter/A;->x()V", 120, "e"),
                    method("Lafter/B;->y()V", 60, "b"),
                ),
                listOf(
                    resource("base/res/layout/renamed.xml", 100, "e"),
                    resource("base/res/drawable/second.png", 300, "d"),
                ),
            ),
        )

        assertEquals(100.0 / 3.0, report.dimensions.getValue(SimilarityDimension.CODE_METHODS))
        assertEquals(0.0, report.dimensions.getValue(SimilarityDimension.LONG_METHODS))
        assertEquals(50.0, report.dimensions.getValue(SimilarityDimension.RESOURCE_STRUCTURE))
        assertEquals(75.0, report.dimensions.getValue(SimilarityDimension.RESOURCE_CONTENT))
        assertTrue(report.overallScore in 0.0..100.0)
    }

    @Test
    fun `duplicate canonical hashes are consumed as a bounded multiset`() {
        val report = FullAabStructuralSimilarityScorerV1.compare(
            profile(
                "1".repeat(64),
                listOf(
                    method("Lbefore/A;->a()V", 60, "a"),
                    method("Lbefore/B;->b()V", 60, "a"),
                ),
                listOf(resource("base/res/raw/a.bin", 10, "c")),
            ),
            profile(
                "2".repeat(64),
                listOf(method("Lafter/A;->x()V", 60, "a")),
                listOf(resource("base/res/raw/a.bin", 10, "c")),
            ),
        )

        assertEquals(50.0, report.dimensions.getValue(SimilarityDimension.CODE_METHODS))
        assertEquals(1, report.topUnchangedCode.size)
    }

    private fun profile(
        hash: String,
        methods: List<MethodFingerprint>,
        resources: List<FullAabResourceFingerprint>,
    ) = FullAabStructuralProfile(hash, 1_000, methods, resources)

    private fun method(identifier: String, instructions: Int, marker: String) = MethodFingerprint(
        identifier,
        instructions,
        marker.repeat(64),
        emptyList(),
        emptyList(),
        emptyList(),
        emptyList(),
    )

    private fun resource(path: String, size: Long, marker: String) = FullAabResourceFingerprint(
        path,
        size,
        marker.repeat(64),
    )
}
