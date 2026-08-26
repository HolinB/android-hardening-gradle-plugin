package com.holin.android.hardening.similarity

import com.holin.android.hardening.state.AtomicFiles
import java.nio.file.Path

class RelativeOwnedArtifactComparisonGate(
    private val minimumImprovementPoints: Double,
) {
    init {
        require(minimumImprovementPoints in 0.01..100.0) {
            "minimumImprovementPoints must be in 0.01..100.0"
        }
    }

    fun verify(baseline: SimilarityReport, candidate: SimilarityReport) {
        require(baseline.scorerVersion == OwnedArtifactSimilarityScorerV1.SCORER_VERSION) {
            "hardening baseline scorer mismatch"
        }
        require(candidate.scorerVersion == baseline.scorerVersion) { "candidate similarity scorer mismatch" }
        val failures = SimilarityDimension.values().mapNotNull { dimension ->
            val baselineScore = baseline.dimensions.getValue(dimension)
            val candidateScore = candidate.dimensions.getValue(dimension)
            val improvement = baselineScore - candidateScore
            if (improvement + EPSILON >= minimumImprovementPoints) null else
                "${dimension.reportKey}: baseline=$baselineScore candidate=$candidateScore improvement=$improvement"
        }
        if (failures.isNotEmpty()) {
            throw RelativeSimilarityGateException(
                "owned artifact similarity must improve every dimension by at least $minimumImprovementPoints points; " +
                    failures.joinToString("; "),
            )
        }
    }

    private companion object {
        const val EPSILON = 1e-12
    }
}

class RelativeSimilarityGateException(message: String) : IllegalStateException(message)

class OwnedArtifactComparisonRunner internal constructor(
    private val analyzer: (OwnedArtifactAnalysisRequest) -> Pair<OwnedArtifactProfile, OwnedArtifactProfile> =
        OwnedArtifactAnalyzer()::analyzePair,
    private val scorer: (OwnedArtifactProfile, OwnedArtifactProfile) -> SimilarityReport =
        OwnedArtifactSimilarityScorerV1::compare,
    private val baselineResourceResolver: (
        Path,
        Map<OwnedResourceKey, OwnedResourceLocation>,
    ) -> Map<OwnedResourceKey, OwnedResourceLocation> = BaselineOwnedResourceLocationResolver()::resolve,
    private val baselineDescriptorAlignmentResolver: (
        Path,
        Set<String>,
    ) -> BaselineOwnedDescriptorAlignment,
) {
    fun compare(
        baselineStore: ImmutableHardeningBaselineStore,
        baselineExpectation: HardeningBaselineExpectation,
        analysisRequest: OwnedArtifactAnalysisRequest,
        minimumImprovementPoints: Double,
        jsonReport: Path,
        markdownReport: Path,
    ): SimilarityReport {
        val baseline = baselineStore.loadForOwnershipReevaluation(baselineExpectation)
        val requestedCurrentDescriptors = analysisRequest.ownedDescriptors.toSet()
        val descriptorAlignment = baselineDescriptorAlignmentResolver(
            baseline.artifacts.hardenedAab,
            requestedCurrentDescriptors,
        )
        require(descriptorAlignment.currentDescriptors.all(requestedCurrentDescriptors::contains)) {
            "baseline descriptor alignment expanded the current owned inventory"
        }
        val baselineRequest = OwnedArtifactAnalysisRequest(
            baseline.artifacts.ordinaryAab,
            baseline.artifacts.hardenedAab,
            baseline.artifacts.ordinaryUniversalApk,
            baseline.artifacts.hardenedUniversalApk,
            descriptorAlignment.baselineDescriptors,
            baselineResourceResolver(
                baseline.artifacts.ordinaryAab,
                analysisRequest.ordinaryOwnedResources,
            ),
            baselineResourceResolver(
                baseline.artifacts.hardenedAab,
                analysisRequest.hardenedOwnedResources,
            ),
        )
        val (baselineOrdinary, baselineHardened) = analyzer(baselineRequest)
        val baselineReport = scorer(baselineOrdinary, baselineHardened)
        val candidateRequest = analysisRequest.copy(
            ownedDescriptors = descriptorAlignment.currentDescriptors,
        )
        val (ordinary, hardened) = analyzer(candidateRequest)
        val candidate = scorer(ordinary, hardened)
        AtomicFiles().replace(jsonReport, SimilarityReportCodec.encode(candidate).toByteArray(Charsets.UTF_8))
        AtomicFiles().replace(markdownReport, SimilarityReportCodec.encodeMarkdown(candidate).toByteArray(Charsets.UTF_8))
        val gate = RelativeOwnedArtifactComparisonGate(minimumImprovementPoints)
        gate.verify(baselineReport, candidate)
        gate.verify(baseline.storedReport, candidate)
        return candidate
    }
}
