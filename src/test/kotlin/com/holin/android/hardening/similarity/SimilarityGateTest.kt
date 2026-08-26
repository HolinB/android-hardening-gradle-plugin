package com.holin.android.hardening.similarity

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SimilarityGateTest {
    @Test
    fun `owned artifact weights produce the expected aggregate`() {
        val report = report(mapOf(
            SimilarityDimension.CODE_METHODS to 50.0,
            SimilarityDimension.LONG_METHODS to 40.0,
            SimilarityDimension.RESOURCE_STRUCTURE to 30.0,
            SimilarityDimension.RESOURCE_CONTENT to 20.0,
        ))

        assertEquals(39.0, report.overallScore, 0.0001)
    }

    @Test
    fun `gate rejects reports from another scorer`() {
        assertFailsWith<SimilarityGateException> {
            SimilarityGate(100.0, 1.0, false, false).verify(report().copy(scorerVersion = "other"))
        }
    }

    private fun report(dimensions: Map<SimilarityDimension, Double> =
        SimilarityDimension.values().associateWith { 0.0 }) = SimilarityReport(
        scorerVersion = "owned-artifact-v1",
        ordinaryAabSha256 = "1".repeat(64),
        hardenedAabSha256 = "2".repeat(64),
        ordinaryUniversalApkSha256 = "3".repeat(64),
        hardenedUniversalApkSha256 = "4".repeat(64),
        ordinaryAabSize = 1_000,
        hardenedAabSize = 1_100,
        ordinaryUniversalApkSize = 800,
        hardenedUniversalApkSize = 900,
        dimensions = dimensions,
    )
}
