package com.holin.android.hardening.similarity

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals

class FullAabSimilarityReportCodecTest {
    @Test
    fun `report explicitly disclaims ownership and is deterministic`() {
        val report = FullAabSimilarityReport(
            FullAabStructuralSimilarityScorerV1.SCORER_VERSION,
            FullAabComparisonScope.FULL_AAB,
            false,
            "1".repeat(64),
            "2".repeat(64),
            100,
            120,
            2,
            3,
            1,
            1,
            4,
            5,
            SimilarityDimension.values().associateWith { 25.0 },
            emptyList(),
            emptyList(),
        )

        val json = FullAabSimilarityReportCodec.encode(report)
        val markdown = FullAabSimilarityReportCodec.encodeMarkdown(report)

        assertEquals(json, FullAabSimilarityReportCodec.encode(report))
        assertContains(json, "\"scope\":\"FULL_AAB\"")
        assertContains(json, "\"ownershipVerified\":false")
        assertContains(markdown, "all DEX and packaged resources are included")
    }
}
