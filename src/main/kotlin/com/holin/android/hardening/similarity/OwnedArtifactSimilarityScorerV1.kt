package com.holin.android.hardening.similarity

import java.util.Locale

/** Scores caller-supplied, exact-owned AAB/APK fingerprints without package-prefix inference. */
object OwnedArtifactSimilarityScorerV1 {
    const val SCORER_VERSION = "owned-artifact-v1"

    fun compare(ordinary: OwnedArtifactProfile, hardened: OwnedArtifactProfile): SimilarityReport {
        val methodMatches = matchMethods(ordinary.methods, hardened.methods)
        val longMethodMatches = matchMethods(
            ordinary.methods.filter { it.instructionCount >= LONG_METHOD_MIN_INSTRUCTIONS },
            hardened.methods.filter { it.instructionCount >= LONG_METHOD_MIN_INSTRUCTIONS },
        )
        val pairedResources = ordinary.resources.mapNotNull { ordinaryResource ->
            hardened.resources.firstOrNull { hardenedResource ->
                hardenedResource.resourceId == ordinaryResource.resourceId &&
                    hardenedResource.qualifier == ordinaryResource.qualifier
            }?.let { ordinaryResource to it }
        }
        return SimilarityReport(
            scorerVersion = SCORER_VERSION,
            ordinaryAabSha256 = ordinary.aabSha256,
            hardenedAabSha256 = hardened.aabSha256,
            ordinaryUniversalApkSha256 = ordinary.universalApkSha256,
            hardenedUniversalApkSha256 = hardened.universalApkSha256,
            ordinaryAabSize = ordinary.aabSize,
            hardenedAabSize = hardened.aabSize,
            ordinaryUniversalApkSize = ordinary.universalApkSize,
            hardenedUniversalApkSize = hardened.universalApkSize,
            dimensions = mapOf(
                SimilarityDimension.CODE_METHODS to methodScore(ordinary.methods, methodMatches),
                SimilarityDimension.LONG_METHODS to methodScore(
                    ordinary.methods.filter { it.instructionCount >= LONG_METHOD_MIN_INSTRUCTIONS },
                    longMethodMatches,
                ),
                SimilarityDimension.RESOURCE_STRUCTURE to resourceStructureScore(ordinary.resources, pairedResources) {
                    before, after ->
                    before.originalEntryName == after.currentEntryName &&
                        before.aabPath == after.aabPath && before.apkPath == after.apkPath
                },
                SimilarityDimension.RESOURCE_CONTENT to resourceScore(ordinary.resources, pairedResources) {
                    before, after -> before.sha256 == after.sha256
                },
            ),
            topUnchangedCode = methodMatches.asSequence()
                .filter { it.similarity == 1.0 }
                .map { match ->
                    CodeSimilarityEvidence(
                        ordinaryDescriptor = match.ordinary.identifier,
                        hardenedDescriptor = match.hardened.identifier,
                        ordinaryInstructionCount = match.ordinary.instructionCount,
                        similarity = match.similarity,
                    )
                }
                .sortedWith(
                    compareByDescending<CodeSimilarityEvidence> { it.ordinaryInstructionCount }
                        .thenBy { it.ordinaryDescriptor }
                        .thenBy { it.hardenedDescriptor },
                )
                .take(EVIDENCE_LIMIT)
                .toList(),
            topUnchangedResources = pairedResources.asSequence()
                .filter { (before, after) -> before.sha256 == after.sha256 }
                .map { (before, _) ->
                    ResourceSimilarityEvidence(before.resourceId, before.qualifier, before.originalEntryName, before.size)
                }
                .sortedWith(
                    compareByDescending<ResourceSimilarityEvidence> { it.ordinarySize }
                        .thenBy { it.resourceId }
                        .thenBy { it.qualifier },
                )
                .take(EVIDENCE_LIMIT)
                .toList(),
        )
    }

    fun methodSimilarity(left: MethodFingerprint, right: MethodFingerprint): Double {
        val opcode = jaccard(shingles(left.opcodeTokens.map(::normalizeOpcode), 5), shingles(right.opcodeTokens.map(::normalizeOpcode), 5))
        val cfg = jaccard(left.blockSignature.map(::normalizeCfg).toSet(), right.blockSignature.map(::normalizeCfg).toSet())
        val api = jaccard(shingles(left.apiCalls.map(::platformCategory), 2), shingles(right.apiCalls.map(::platformCategory), 2))
        val strings = jaccard(left.constants.map(::stringLengthCategory).toSet(), right.constants.map(::stringLengthCategory).toSet())
        return OPCODE_WEIGHT * opcode + CFG_WEIGHT * cfg + API_WEIGHT * api + STRING_WEIGHT * strings
    }

    private fun matchMethods(
        ordinary: List<MethodFingerprint>,
        hardened: List<MethodFingerprint>,
    ): List<MethodMatch> {
        val used = mutableSetOf<Int>()
        return ordinary.sortedWith(compareByDescending<MethodFingerprint> { it.instructionCount }.thenBy { it.identifier })
            .mapNotNull { before ->
                hardened.indices.asSequence().filterNot(used::contains).map { index ->
                    MethodMatch(before, hardened[index], methodSimilarity(before, hardened[index]), index)
                }.maxWithOrNull(
                    compareBy<MethodMatch> { it.similarity }
                        .thenByDescending { kotlin.math.abs(it.ordinary.instructionCount - it.hardened.instructionCount) }
                        .thenByDescending { it.hardened.identifier },
                )?.also { used += it.hardenedIndex }
            }
    }

    private fun methodScore(ordinary: List<MethodFingerprint>, matches: List<MethodMatch>): Double {
        if (ordinary.isEmpty()) return 100.0
        val byIdentifier = matches.associateBy { it.ordinary.identifier }
        val matchedMass = ordinary.sumOf { method ->
            method.instructionCount.toDouble() * (byIdentifier[method.identifier]?.similarity ?: 0.0)
        }
        val totalMass = ordinary.sumOf(MethodFingerprint::instructionCount)
        return if (totalMass == 0) 100.0 else 100.0 * matchedMass / totalMass
    }

    private fun resourceScore(
        ordinary: List<OwnedResourceFingerprint>,
        pairs: List<Pair<OwnedResourceFingerprint, OwnedResourceFingerprint>>,
        matches: (OwnedResourceFingerprint, OwnedResourceFingerprint) -> Boolean,
    ): Double {
        if (ordinary.isEmpty()) return 100.0
        val matchedKeys = pairs.asSequence().filter { (before, after) -> matches(before, after) }
            .map { (before, _) -> before.resourceId to before.qualifier }.toSet()
        val totalMass = ordinary.sumOf(OwnedResourceFingerprint::size)
        if (totalMass == 0L) return 100.0
        val matchedMass = ordinary.filter { it.resourceId to it.qualifier in matchedKeys }.sumOf(OwnedResourceFingerprint::size)
        return 100.0 * matchedMass / totalMass
    }

    private fun resourceStructureScore(
        ordinary: List<OwnedResourceFingerprint>,
        pairs: List<Pair<OwnedResourceFingerprint, OwnedResourceFingerprint>>,
        matches: (OwnedResourceFingerprint, OwnedResourceFingerprint) -> Boolean,
    ): Double {
        if (ordinary.isEmpty()) return 100.0
        return 100.0 * pairs.count { (before, after) -> matches(before, after) } / ordinary.size
    }

    private fun normalizeOpcode(value: String): String = value.lowercase(Locale.ROOT)
        .replace(REGISTER, "v#")
        .replace(BRANCH_OFFSET, "@#")
        .replace(NUMERIC_LITERAL, "#")
        .trim()

    private fun normalizeCfg(value: String): String = normalizeOpcode(value).replace(DEBUG_OFFSET, "debug#")

    private fun platformCategory(value: String): String {
        val normalized = normalizeOpcode(value)
        return when {
            normalized.startsWith("landroid/") -> "android"
            normalized.startsWith("ljava/") -> "java"
            normalized.startsWith("ljavax/") -> "javax"
            normalized.startsWith("lkotlin/") || normalized.startsWith("lkotlinx/") -> "kotlin"
            else -> normalized.substringBefore("->").substringBefore(':').substringBefore('/')
        }
    }

    private fun stringLengthCategory(value: String): String {
        val normalized = value.lowercase(Locale.ROOT)
        if (normalized.startsWith("string:")) return normalized
        val length = value.length
        return when {
            length == 0 -> "string:empty"
            length <= 8 -> "string:short"
            length <= 32 -> "string:medium"
            length <= 128 -> "string:long"
            else -> "string:very-long"
        }
    }

    private fun shingles(values: List<String>, width: Int): Set<String> {
        if (values.isEmpty()) return emptySet()
        if (values.size < width) return setOf(values.joinToString("\u001f"))
        return (0..values.size - width).mapTo(linkedSetOf()) { values.subList(it, it + width).joinToString("\u001f") }
    }

    private fun jaccard(left: Set<String>, right: Set<String>): Double {
        if (left.isEmpty() && right.isEmpty()) return 1.0
        return (left intersect right).size.toDouble() / (left union right).size
    }

    private data class MethodMatch(
        val ordinary: MethodFingerprint,
        val hardened: MethodFingerprint,
        val similarity: Double,
        val hardenedIndex: Int,
    )

    private const val LONG_METHOD_MIN_INSTRUCTIONS = 100
    private const val EVIDENCE_LIMIT = 10
    private const val OPCODE_WEIGHT = 0.45
    private const val CFG_WEIGHT = 0.30
    private const val API_WEIGHT = 0.15
    private const val STRING_WEIGHT = 0.10
    private val REGISTER = Regex("(?:^|[^a-z0-9_])([vp][0-9]+)(?=$|[^a-z0-9_])")
    private val BRANCH_OFFSET = Regex("(?:[+-]0x[0-9a-f]+|@[0-9]+)")
    private val DEBUG_OFFSET = Regex("debug(?:[_-]?offset)?[=:]?[0-9]+")
    private val NUMERIC_LITERAL = Regex("(?<![a-z0-9_])(?:0x[0-9a-f]+|[+-]?[0-9]+)(?![a-z0-9_])")
}
