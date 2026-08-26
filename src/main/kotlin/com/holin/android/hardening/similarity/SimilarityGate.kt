package com.holin.android.hardening.similarity

import kotlin.math.max

enum class SimilarityDimension(val reportKey: String, val weight: Int) {
    CODE_METHODS("code_methods", 40),
    LONG_METHODS("long_methods", 25),
    RESOURCE_STRUCTURE("resource_structure", 20),
    RESOURCE_CONTENT("resource_content", 15),
}

enum class ArtifactComparisonMode {
    DUAL_AAB_APK,
    AAB_ONLY,
}

class SimilarityReport(
    val scorerVersion: String,
    val ordinaryAabSha256: String,
    val hardenedAabSha256: String,
    val ordinaryUniversalApkSha256: String?,
    val hardenedUniversalApkSha256: String?,
    val ordinaryAabSize: Long,
    val hardenedAabSize: Long,
    val ordinaryUniversalApkSize: Long?,
    val hardenedUniversalApkSize: Long?,
    val dimensions: Map<SimilarityDimension, Double>,
    topUnchangedCode: List<CodeSimilarityEvidence> = emptyList(),
    topUnchangedResources: List<ResourceSimilarityEvidence> = emptyList(),
) {
    val comparisonMode: ArtifactComparisonMode = if (ordinaryUniversalApkSha256 == null) {
        ArtifactComparisonMode.AAB_ONLY
    } else {
        ArtifactComparisonMode.DUAL_AAB_APK
    }
    val topUnchangedCode: List<CodeSimilarityEvidence> = topUnchangedCode.sortedWith(
        compareByDescending<CodeSimilarityEvidence> { it.ordinaryInstructionCount }
            .thenBy { it.ordinaryDescriptor }
            .thenBy { it.hardenedDescriptor },
    )
    val topUnchangedResources: List<ResourceSimilarityEvidence> = topUnchangedResources.sortedWith(
        compareByDescending<ResourceSimilarityEvidence> { it.ordinarySize }
            .thenBy { it.resourceId }
            .thenBy { it.qualifier },
    )

    init {
        require(scorerVersion.isNotBlank()) { "scorerVersion must not be blank" }
        require(SHA_256.matches(ordinaryAabSha256) && SHA_256.matches(hardenedAabSha256)) {
            "AAB hashes must be lowercase SHA-256"
        }
        require((ordinaryUniversalApkSha256 == null) == (ordinaryUniversalApkSize == null) &&
            (hardenedUniversalApkSha256 == null) == (hardenedUniversalApkSize == null) &&
            (ordinaryUniversalApkSha256 == null) == (hardenedUniversalApkSha256 == null)) {
            "universal APK provenance must be present for both artifacts or absent for both"
        }
        require(ordinaryUniversalApkSha256 == null ||
            (SHA_256.matches(ordinaryUniversalApkSha256) && SHA_256.matches(hardenedUniversalApkSha256!!))) {
            "universal APK hashes must be lowercase SHA-256"
        }
        require(ordinaryAabSize > 0L && hardenedAabSize > 0L &&
            (ordinaryUniversalApkSize == null || ordinaryUniversalApkSize > 0L) &&
            (hardenedUniversalApkSize == null || hardenedUniversalApkSize > 0L)) {
            "artifact sizes must be greater than zero"
        }
        require(dimensions.keys == SimilarityDimension.values().toSet()) {
            "dimensions must contain exactly ${SimilarityDimension.values().map { it.reportKey }}"
        }
        require(dimensions.values.all { it.isFinite() && it in 0.0..100.0 }) {
            "similarity dimension scores must be in 0.0..100.0"
        }
    }

    val overallScore: Double = SimilarityDimension.values().sumOf { dimension ->
        dimensions.getValue(dimension) * dimension.weight / 100.0
    }
    val growth: Double = (hardenedAabSize.toDouble() - ordinaryAabSize.toDouble()) / ordinaryAabSize.toDouble()

    fun copy(
        scorerVersion: String = this.scorerVersion,
        ordinaryAabSha256: String = this.ordinaryAabSha256,
        hardenedAabSha256: String = this.hardenedAabSha256,
        ordinaryUniversalApkSha256: String? = this.ordinaryUniversalApkSha256,
        hardenedUniversalApkSha256: String? = this.hardenedUniversalApkSha256,
        ordinaryAabSize: Long = this.ordinaryAabSize,
        hardenedAabSize: Long = this.hardenedAabSize,
        ordinaryUniversalApkSize: Long? = this.ordinaryUniversalApkSize,
        hardenedUniversalApkSize: Long? = this.hardenedUniversalApkSize,
        dimensions: Map<SimilarityDimension, Double> = this.dimensions,
        topUnchangedCode: List<CodeSimilarityEvidence> = this.topUnchangedCode,
        topUnchangedResources: List<ResourceSimilarityEvidence> = this.topUnchangedResources,
    ) = SimilarityReport(
        scorerVersion, ordinaryAabSha256, hardenedAabSha256,
        ordinaryUniversalApkSha256, hardenedUniversalApkSha256,
        ordinaryAabSize, hardenedAabSize, ordinaryUniversalApkSize, hardenedUniversalApkSize,
        dimensions, topUnchangedCode, topUnchangedResources,
    )

    override fun equals(other: Any?): Boolean = other is SimilarityReport &&
        scorerVersion == other.scorerVersion &&
        ordinaryAabSha256 == other.ordinaryAabSha256 && hardenedAabSha256 == other.hardenedAabSha256 &&
        ordinaryUniversalApkSha256 == other.ordinaryUniversalApkSha256 &&
        hardenedUniversalApkSha256 == other.hardenedUniversalApkSha256 &&
        ordinaryAabSize == other.ordinaryAabSize && hardenedAabSize == other.hardenedAabSize &&
        ordinaryUniversalApkSize == other.ordinaryUniversalApkSize && hardenedUniversalApkSize == other.hardenedUniversalApkSize &&
        dimensions == other.dimensions && topUnchangedCode == other.topUnchangedCode && topUnchangedResources == other.topUnchangedResources

    override fun hashCode(): Int = listOf(
        scorerVersion, ordinaryAabSha256, hardenedAabSha256, ordinaryUniversalApkSha256,
        hardenedUniversalApkSha256, ordinaryAabSize, hardenedAabSize, ordinaryUniversalApkSize,
        hardenedUniversalApkSize, dimensions, topUnchangedCode, topUnchangedResources,
    ).hashCode()
}

class SimilarityGate(
    private val maximumOverallExclusive: Double,
    private val maximumGrowth: Double,
    private val enforceMaximumOverall: Boolean = true,
    private val enforceMaximumGrowth: Boolean = true,
) {
    init {
        require(maximumOverallExclusive in 0.0..100.0) { "maximumOverallExclusive must be in 0.0..100.0" }
        require(maximumGrowth in 0.0..1.0) { "maximumGrowth must be in 0.0..1.0" }
    }

    fun verify(report: SimilarityReport) {
        if (report.scorerVersion != OwnedArtifactSimilarityScorerV1.SCORER_VERSION) {
            throw SimilarityGateException("unexpected owned artifact similarity scorer ${report.scorerVersion}")
        }
        if (enforceMaximumOverall && report.overallScore >= maximumOverallExclusive) {
            throw SimilarityGateException(
                "owned artifact similarity ${format(report.overallScore)} must be below ${format(maximumOverallExclusive)}",
            )
        }
        if (enforceMaximumGrowth && report.growth > maximumGrowth) {
            throw SimilarityGateException(
                "hardened AAB growth ${format(report.growth * 100.0)}% exceeds ${format(maximumGrowth * 100.0)}%",
            )
        }
    }

    private fun format(value: Double): String = "%.2f".format(java.util.Locale.ROOT, max(0.0, value))
}

class SimilarityGateException(message: String) : IllegalStateException(message)
