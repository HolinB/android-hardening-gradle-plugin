package com.holin.android.hardening.similarity

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class OwnedSimilarityReportCodecTest {
    @Test
    fun `json is deterministic and strictly round trips four artifact provenance and evidence`() {
        val report = report()

        val first = SimilarityReportCodec.encode(report)
        val second = SimilarityReportCodec.encode(report)

        assertEquals(first, second)
        assertEquals(report, SimilarityReportCodec.decode(first))
        assertTrue(first.indexOf("code_methods") < first.indexOf("long_methods"))
        assertFailsWith<IllegalArgumentException> {
            SimilarityReportCodec.decode(first.replaceFirst("{", "{\"unexpected\":true,"))
        }
    }

    @Test
    fun `markdown is deterministic and orders unchanged evidence`() {
        val markdown = SimilarityReportCodec.encodeMarkdown(report())

        assertEquals(markdown, SimilarityReportCodec.encodeMarkdown(report()))
        assertTrue(markdown.indexOf("Lbefore/A;->a()V") < markdown.indexOf("Lbefore/Z;->z()V"))
        assertTrue(markdown.contains("ordinary universal APK"))
    }

    @Test
    fun `json preserves non terminating double values exactly`() {
        val report = report(SimilarityDimension.values().associateWith { 1.0 / 3.0 })

        assertEquals(report, SimilarityReportCodec.decode(SimilarityReportCodec.encode(report)))
    }

    private fun report(dimensions: Map<SimilarityDimension, Double> =
        SimilarityDimension.values().associateWith { it.ordinal * 10.0 }) = SimilarityReport(
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
        topUnchangedCode = listOf(
            CodeSimilarityEvidence("Lbefore/Z;->z()V", "Lafter/Z;->z()V", 10, 1.0),
            CodeSimilarityEvidence("Lbefore/A;->a()V", "Lafter/A;->a()V", 20, 1.0),
        ),
        topUnchangedResources = listOf(
            ResourceSimilarityEvidence(7, "land", "screen", 200),
        ),
    )
}
