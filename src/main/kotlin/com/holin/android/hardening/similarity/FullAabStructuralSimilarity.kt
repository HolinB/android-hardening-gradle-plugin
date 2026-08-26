package com.holin.android.hardening.similarity

import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.holin.android.hardening.artifact.BundleZipRewriter
import com.holin.android.hardening.state.Sha256
import groovy.json.JsonOutput
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.ArrayDeque
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

enum class FullAabComparisonScope { FULL_AAB }

data class FullAabResourceFingerprint(
    val path: String,
    val size: Long,
    val sha256: String,
) {
    init {
        BundleZipRewriter.requireSafeUniqueEntryNames(listOf(path))
        require(size >= 0L) { "full-AAB resource size must not be negative" }
        require(SHA_256.matches(sha256)) { "full-AAB resource hash must be lowercase SHA-256" }
    }
}

data class FullAabStructuralProfile(
    val aabSha256: String,
    val aabSize: Long,
    val methods: List<MethodFingerprint>,
    val resources: List<FullAabResourceFingerprint>,
) {
    init {
        require(SHA_256.matches(aabSha256)) { "full-AAB hash must be lowercase SHA-256" }
        require(aabSize > 0L) { "full-AAB size must be greater than zero" }
        require(methods.map(MethodFingerprint::identifier).toSet().size == methods.size) {
            "full-AAB method identifiers must be unique"
        }
        require(methods.all { SHA_256.matches(it.canonicalHash) }) {
            "full-AAB method canonical hashes must be lowercase SHA-256"
        }
        require(resources.map(FullAabResourceFingerprint::path).toSet().size == resources.size) {
            "full-AAB resource paths must be unique"
        }
    }
}

data class FullAabCodeEvidence(
    val referenceDescriptor: String,
    val candidateDescriptor: String,
    val referenceInstructionCount: Int,
    val canonicalHash: String,
)

data class FullAabResourceEvidence(
    val referencePath: String,
    val candidatePath: String,
    val referenceSize: Long,
    val sha256: String,
)

class FullAabSimilarityReport(
    val scorerVersion: String,
    val scope: FullAabComparisonScope,
    val ownershipVerified: Boolean,
    val referenceAabSha256: String,
    val candidateAabSha256: String,
    val referenceAabSize: Long,
    val candidateAabSize: Long,
    val referenceMethodCount: Int,
    val candidateMethodCount: Int,
    val referenceLongMethodCount: Int,
    val candidateLongMethodCount: Int,
    val referenceResourceCount: Int,
    val candidateResourceCount: Int,
    val dimensions: Map<SimilarityDimension, Double>,
    topUnchangedCode: List<FullAabCodeEvidence>,
    topUnchangedResources: List<FullAabResourceEvidence>,
) {
    val topUnchangedCode = topUnchangedCode.sortedWith(
        compareByDescending<FullAabCodeEvidence> { it.referenceInstructionCount }
            .thenBy { it.referenceDescriptor }
            .thenBy { it.candidateDescriptor },
    )
    val topUnchangedResources = topUnchangedResources.sortedWith(
        compareByDescending<FullAabResourceEvidence> { it.referenceSize }
            .thenBy { it.referencePath }
            .thenBy { it.candidatePath },
    )
    val overallScore: Double = SimilarityDimension.values().sumOf { dimension ->
        dimensions.getValue(dimension) * dimension.weight / 100.0
    }
    val growth: Double = (candidateAabSize.toDouble() - referenceAabSize) / referenceAabSize

    init {
        require(scorerVersion.isNotBlank()) { "full-AAB scorer version must not be blank" }
        require(scope == FullAabComparisonScope.FULL_AAB && !ownershipVerified) {
            "external AAB comparison must not claim unproven ownership"
        }
        require(SHA_256.matches(referenceAabSha256) && SHA_256.matches(candidateAabSha256)) {
            "full-AAB provenance hashes must be lowercase SHA-256"
        }
        require(referenceAabSize > 0L && candidateAabSize > 0L) { "full-AAB sizes must be positive" }
        require(
            listOf(
                referenceMethodCount, candidateMethodCount, referenceLongMethodCount,
                candidateLongMethodCount, referenceResourceCount, candidateResourceCount,
            ).all { it >= 0 },
        ) { "full-AAB inventory counts must not be negative" }
        require(dimensions.keys == SimilarityDimension.values().toSet()) {
            "full-AAB report must contain all similarity dimensions"
        }
        require(dimensions.values.all { it.isFinite() && it in 0.0..100.0 }) {
            "full-AAB similarity scores must be in 0.0..100.0"
        }
    }
}

/**
 * Deterministic, indexed full-AAB comparison for external artifacts whose app ownership cannot be proven.
 * Method matching is a bounded canonical-hash multiset operation, never an all-pairs scan.
 */
object FullAabStructuralSimilarityScorerV1 {
    const val SCORER_VERSION = "full-aab-structural-v1"
    private const val LONG_METHOD_MIN_INSTRUCTIONS = 100
    private const val EVIDENCE_LIMIT = 20

    fun compare(reference: FullAabStructuralProfile, candidate: FullAabStructuralProfile): FullAabSimilarityReport {
        val methodMatches = exactMethodMatches(reference.methods, candidate.methods)
        val referenceLong = reference.methods.filter { it.instructionCount >= LONG_METHOD_MIN_INSTRUCTIONS }
        val candidateLong = candidate.methods.filter { it.instructionCount >= LONG_METHOD_MIN_INSTRUCTIONS }
        val longMatches = exactMethodMatches(referenceLong, candidateLong)
        val candidateResourcesByPath = candidate.resources.associateBy(FullAabResourceFingerprint::path)
        val structureMatches = reference.resources.count { before ->
            candidateResourcesByPath.containsKey(before.path)
        }
        val contentMatches = exactResourceContentMatches(reference.resources, candidate.resources)
        return FullAabSimilarityReport(
            SCORER_VERSION,
            FullAabComparisonScope.FULL_AAB,
            false,
            reference.aabSha256,
            candidate.aabSha256,
            reference.aabSize,
            candidate.aabSize,
            reference.methods.size,
            candidate.methods.size,
            referenceLong.size,
            candidateLong.size,
            reference.resources.size,
            candidate.resources.size,
            mapOf(
                SimilarityDimension.CODE_METHODS to weightedMethodScore(reference.methods, methodMatches),
                SimilarityDimension.LONG_METHODS to weightedMethodScore(referenceLong, longMatches),
                SimilarityDimension.RESOURCE_STRUCTURE to percentage(structureMatches.toLong(), reference.resources.size.toLong()),
                SimilarityDimension.RESOURCE_CONTENT to weightedResourceScore(reference.resources, contentMatches),
            ),
            methodMatches.asSequence()
                .map { match ->
                    FullAabCodeEvidence(
                        match.reference.identifier,
                        match.candidate.identifier,
                        match.reference.instructionCount,
                        match.reference.canonicalHash,
                    )
                }
                .sortedWith(
                    compareByDescending<FullAabCodeEvidence> { it.referenceInstructionCount }
                        .thenBy { it.referenceDescriptor }
                        .thenBy { it.candidateDescriptor },
                )
                .take(EVIDENCE_LIMIT)
                .toList(),
            contentMatches.asSequence()
                .map { match ->
                    FullAabResourceEvidence(
                        match.reference.path,
                        match.candidate.path,
                        match.reference.size,
                        match.reference.sha256,
                    )
                }
                .sortedWith(
                    compareByDescending<FullAabResourceEvidence> { it.referenceSize }
                        .thenBy { it.referencePath }
                        .thenBy { it.candidatePath },
                )
                .take(EVIDENCE_LIMIT)
                .toList(),
        )
    }

    private fun exactMethodMatches(
        reference: List<MethodFingerprint>,
        candidate: List<MethodFingerprint>,
    ): List<MethodMatch> {
        val candidatesByHash = candidate.groupBy(MethodFingerprint::canonicalHash)
            .mapValuesTo(linkedMapOf()) { (_, values) ->
                ArrayDeque(values.sortedWith(compareBy(MethodFingerprint::identifier).thenBy(MethodFingerprint::instructionCount)))
            }
        return reference.sortedWith(compareByDescending<MethodFingerprint> { it.instructionCount }.thenBy { it.identifier })
            .mapNotNull { before ->
                candidatesByHash[before.canonicalHash]?.pollFirst()?.let { after -> MethodMatch(before, after) }
            }
    }

    private fun exactResourceContentMatches(
        reference: List<FullAabResourceFingerprint>,
        candidate: List<FullAabResourceFingerprint>,
    ): List<ResourceMatch> {
        val candidatesByHash = candidate.groupBy(FullAabResourceFingerprint::sha256)
            .mapValuesTo(linkedMapOf()) { (_, values) -> ArrayDeque(values.sortedBy(FullAabResourceFingerprint::path)) }
        return reference.sortedWith(compareByDescending<FullAabResourceFingerprint> { it.size }.thenBy { it.path })
            .mapNotNull { before ->
                candidatesByHash[before.sha256]?.pollFirst()?.let { after -> ResourceMatch(before, after) }
            }
    }

    private fun weightedMethodScore(reference: List<MethodFingerprint>, matches: List<MethodMatch>): Double {
        val total = reference.sumOf { it.instructionCount.toLong() }
        val matched = matches.sumOf { it.reference.instructionCount.toLong() }
        return percentage(matched, total)
    }

    private fun weightedResourceScore(
        reference: List<FullAabResourceFingerprint>,
        matches: List<ResourceMatch>,
    ): Double = percentage(matches.sumOf { it.reference.size }, reference.sumOf(FullAabResourceFingerprint::size))

    private fun percentage(matched: Long, total: Long): Double = if (total == 0L) 100.0 else 100.0 * matched / total

    private data class MethodMatch(val reference: MethodFingerprint, val candidate: MethodFingerprint)
    private data class ResourceMatch(val reference: FullAabResourceFingerprint, val candidate: FullAabResourceFingerprint)
}

class FullAabStructuralAnalyzer {
    fun analyze(path: Path): FullAabStructuralProfile {
        val input = path.toAbsolutePath().normalize()
        require(input.fileName.toString().lowercase().endsWith(".aab")) {
            "external hardening comparison input must use the .aab extension: $input"
        }
        require(Files.isRegularFile(input, NOFOLLOW_LINKS) && !Files.isSymbolicLink(input)) {
            "external hardening comparison input is not a non-symlink regular AAB: $input"
        }
        require(Files.size(input) in 1..MAX_AAB_BYTES) { "external hardening comparison AAB has an invalid size" }
        val fingerprinter = OwnedArtifactAnalyzer()
        val methods = linkedMapOf<String, MethodFingerprint>()
        val resources = mutableListOf<FullAabResourceFingerprint>()
        ZipFile(input.toFile()).use { zip ->
            val entries = zip.entries().asSequence().toList()
            BundleZipRewriter.requireSafeUniqueEntryNames(entries.map(ZipEntry::getName))
            val dexEntries = entries.filter { !it.isDirectory && DEX_PATH.matches(it.name) }.sortedBy(ZipEntry::getName)
            require(dexEntries.isNotEmpty()) { "external hardening comparison AAB contains no DEX entries" }
            dexEntries.forEach { entry ->
                val bytes = readBounded(zip, entry, MAX_DEX_ENTRY_BYTES)
                val dex = try {
                    DexBackedDexFile(Opcodes.getDefault(), bytes)
                } catch (failure: RuntimeException) {
                    throw IllegalArgumentException("invalid external comparison DEX entry ${entry.name}", failure)
                }
                dex.classes.sortedBy { it.type }.forEach { classDef ->
                    classDef.methods.asSequence().mapNotNull { method ->
                        val instructions = method.implementation?.instructions?.toList() ?: return@mapNotNull null
                        if (instructions.size < MIN_METHOD_INSTRUCTIONS) return@mapNotNull null
                        val descriptor = "(${method.parameterTypes.joinToString("")})${method.returnType}"
                        val identifier = "${classDef.type}->${method.name}$descriptor"
                        identifier to fingerprinter.fingerprint(identifier, instructions)
                    }.forEach { (identifier, fingerprint) ->
                        require(methods.put(identifier, fingerprint) == null) {
                            "duplicate method $identifier across external comparison AAB multidex"
                        }
                    }
                }
            }
            entries.asSequence()
                .filter { !it.isDirectory && isResourceEntry(it.name) }
                .sortedBy(ZipEntry::getName)
                .forEach { entry ->
                    val bytes = readBounded(zip, entry, MAX_RESOURCE_ENTRY_BYTES)
                    resources += FullAabResourceFingerprint(entry.name, bytes.size.toLong(), Sha256.hex(bytes))
                }
        }
        require(methods.isNotEmpty()) { "external hardening comparison AAB contains no eligible methods" }
        require(resources.isNotEmpty()) { "external hardening comparison AAB contains no resource entries" }
        return FullAabStructuralProfile(
            Sha256.file(input),
            Files.size(input),
            methods.values.toList(),
            resources,
        )
    }

    private fun readBounded(zip: ZipFile, entry: ZipEntry, maximumBytes: Long): ByteArray {
        require(entry.size < 0L || entry.size <= maximumBytes) { "AAB entry ${entry.name} exceeds analysis size limit" }
        val output = ByteArrayOutputStream(if (entry.size in 0..Int.MAX_VALUE.toLong()) entry.size.toInt() else 8192)
        zip.getInputStream(entry).use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            var total = 0L
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                require(total <= maximumBytes) { "AAB entry ${entry.name} exceeds analysis size limit" }
                output.write(buffer, 0, count)
            }
        }
        return output.toByteArray()
    }

    private fun isResourceEntry(path: String): Boolean = RESOURCE_PATH.matches(path) || RESOURCE_TABLE_PATH.matches(path)

    private companion object {
        const val MIN_METHOD_INSTRUCTIONS = 12
        const val MAX_AAB_BYTES = 2L * 1024 * 1024 * 1024
        const val MAX_DEX_ENTRY_BYTES = 256L * 1024 * 1024
        const val MAX_RESOURCE_ENTRY_BYTES = 256L * 1024 * 1024
        val DEX_PATH = Regex("^[^/]+/dex/classes(?:[0-9]+)?\\.dex$")
        val RESOURCE_PATH = Regex("^[^/]+/res/[^/]+/[^/]+$")
        val RESOURCE_TABLE_PATH = Regex("^[^/]+/resources\\.pb$")
    }
}

object FullAabSimilarityReportCodec {
    fun encode(report: FullAabSimilarityReport): String = buildString {
        append("{\"schemaVersion\":1")
        append(",\"scorerVersion\":").append(json(report.scorerVersion))
        append(",\"scope\":").append(json(report.scope.name))
        append(",\"ownershipVerified\":").append(report.ownershipVerified)
        append(",\"referenceAabSha256\":").append(json(report.referenceAabSha256))
        append(",\"candidateAabSha256\":").append(json(report.candidateAabSha256))
        append(",\"referenceAabSize\":").append(report.referenceAabSize)
        append(",\"candidateAabSize\":").append(report.candidateAabSize)
        append(",\"growth\":").append(report.growth)
        append(",\"inventory\":{")
        append("\"referenceMethods\":").append(report.referenceMethodCount)
        append(",\"candidateMethods\":").append(report.candidateMethodCount)
        append(",\"referenceLongMethods\":").append(report.referenceLongMethodCount)
        append(",\"candidateLongMethods\":").append(report.candidateLongMethodCount)
        append(",\"referenceResources\":").append(report.referenceResourceCount)
        append(",\"candidateResources\":").append(report.candidateResourceCount).append('}')
        append(",\"dimensions\":{")
        SimilarityDimension.values().forEachIndexed { index, dimension ->
            if (index > 0) append(',')
            append(json(dimension.reportKey)).append(':').append(report.dimensions.getValue(dimension))
        }
        append("},\"overallScore\":").append(report.overallScore)
        append(",\"topUnchangedCode\":[")
        report.topUnchangedCode.forEachIndexed { index, evidence ->
            if (index > 0) append(',')
            append("{\"referenceDescriptor\":").append(json(evidence.referenceDescriptor))
            append(",\"candidateDescriptor\":").append(json(evidence.candidateDescriptor))
            append(",\"referenceInstructionCount\":").append(evidence.referenceInstructionCount)
            append(",\"canonicalHash\":").append(json(evidence.canonicalHash)).append('}')
        }
        append("],\"topUnchangedResources\":[")
        report.topUnchangedResources.forEachIndexed { index, evidence ->
            if (index > 0) append(',')
            append("{\"referencePath\":").append(json(evidence.referencePath))
            append(",\"candidatePath\":").append(json(evidence.candidatePath))
            append(",\"referenceSize\":").append(evidence.referenceSize)
            append(",\"sha256\":").append(json(evidence.sha256)).append('}')
        }
        append("]}\n")
    }

    fun encodeMarkdown(report: FullAabSimilarityReport): String = buildString {
        append("# External AAB Similarity Report\n\n")
        append("- scorer: `").append(report.scorerVersion).append("`\n")
        append("- scope: `").append(report.scope.name).append("`\n")
        append("- ownership verified: `false`\n")
        append("- note: the reference AAB has no trusted ownership inventory or mapping; all DEX and packaged resources are included.\n\n")
        append("| dimension | similarity | weight |\n| --- | ---: | ---: |\n")
        SimilarityDimension.values().forEach { dimension ->
            append("| ").append(dimension.reportKey).append(" | ")
                .append(format(report.dimensions.getValue(dimension))).append(" | ")
                .append(dimension.weight).append("% |\n")
        }
        append("\noverall: **").append(format(report.overallScore)).append("**\n\n")
        append("## Provenance\n\n")
        append("- reference AAB: `").append(report.referenceAabSha256).append("` (")
            .append(report.referenceAabSize).append(" bytes)\n")
        append("- hardened candidate AAB: `").append(report.candidateAabSha256).append("` (")
            .append(report.candidateAabSize).append(" bytes)\n")
        append("- size growth relative to reference: ").append(format(report.growth * 100.0)).append("%\n\n")
        append("## Inventory\n\n")
        append("| kind | reference | candidate |\n| --- | ---: | ---: |\n")
        append("| eligible methods | ").append(report.referenceMethodCount).append(" | ")
            .append(report.candidateMethodCount).append(" |\n")
        append("| long methods | ").append(report.referenceLongMethodCount).append(" | ")
            .append(report.candidateLongMethodCount).append(" |\n")
        append("| resource entries | ").append(report.referenceResourceCount).append(" | ")
            .append(report.candidateResourceCount).append(" |\n\n")
        append("## Largest Exact Code Matches\n\n")
        if (report.topUnchangedCode.isEmpty()) append("None\n") else report.topUnchangedCode.forEach { evidence ->
            append("- `").append(evidence.referenceDescriptor).append("` -> `")
                .append(evidence.candidateDescriptor).append("` (")
                .append(evidence.referenceInstructionCount).append(" instructions)\n")
        }
        append("\n## Largest Exact Resource Matches\n\n")
        if (report.topUnchangedResources.isEmpty()) append("None\n") else report.topUnchangedResources.forEach { evidence ->
            append("- `").append(evidence.referencePath).append("` -> `")
                .append(evidence.candidatePath).append("` (")
                .append(evidence.referenceSize).append(" bytes)\n")
        }
    }

    private fun json(value: String): String = JsonOutput.toJson(value)
    private fun format(value: Double): String = "%.4f".format(java.util.Locale.ROOT, value)
}
