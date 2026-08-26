package com.holin.android.hardening.similarity

import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonSlurper

/** Canonical, strict persistence and human-readable rendering for owned reports. */
object SimilarityReportCodec {
    fun encode(report: SimilarityReport): String = buildString {
        append("{\"schemaVersion\":2")
        append(",\"scorerVersion\":").append(json(report.scorerVersion))
        append(",\"comparisonMode\":").append(json(report.comparisonMode.name))
        append(",\"ordinaryAabSha256\":").append(json(report.ordinaryAabSha256))
        append(",\"hardenedAabSha256\":").append(json(report.hardenedAabSha256))
        append(",\"ordinaryUniversalApkSha256\":").append(jsonOrNull(report.ordinaryUniversalApkSha256))
        append(",\"hardenedUniversalApkSha256\":").append(jsonOrNull(report.hardenedUniversalApkSha256))
        append(",\"ordinaryAabSize\":").append(report.ordinaryAabSize)
        append(",\"hardenedAabSize\":").append(report.hardenedAabSize)
        append(",\"ordinaryUniversalApkSize\":").append(report.ordinaryUniversalApkSize ?: "null")
        append(",\"hardenedUniversalApkSize\":").append(report.hardenedUniversalApkSize ?: "null")
        append(",\"dimensions\":{")
        SimilarityDimension.values().forEachIndexed { index, dimension ->
            if (index > 0) append(',')
            append(json(dimension.reportKey)).append(':').append(number(report.dimensions.getValue(dimension)))
        }
        append("},\"overallScore\":").append(number(report.overallScore))
        append(",\"growth\":").append(number(report.growth))
        append(",\"topUnchangedCode\":[")
        report.topUnchangedCode.forEachIndexed { index, evidence ->
            if (index > 0) append(',')
            append("{\"ordinaryDescriptor\":").append(json(evidence.ordinaryDescriptor))
            append(",\"hardenedDescriptor\":").append(json(evidence.hardenedDescriptor))
            append(",\"ordinaryInstructionCount\":").append(evidence.ordinaryInstructionCount)
            append(",\"similarity\":").append(number(evidence.similarity)).append('}')
        }
        append("],\"topUnchangedResources\":[")
        report.topUnchangedResources.forEachIndexed { index, evidence ->
            if (index > 0) append(',')
            append("{\"resourceId\":").append(evidence.resourceId)
            append(",\"qualifier\":").append(json(evidence.qualifier))
            append(",\"ordinaryEntryName\":").append(json(evidence.ordinaryEntryName))
            append(",\"ordinarySize\":").append(evidence.ordinarySize).append('}')
        }
        append("]}\n")
    }

    fun decode(text: String): SimilarityReport {
        StrictJson.validateDocument(text)
        val root = JsonSlurper().parseText(text).asMap("similarity report")
        root.keysExactly(ROOT_KEYS, "similarity report")
        require(root.integer("schemaVersion") == 2) { "unsupported similarity report schema" }
        val dimensionsMap = root["dimensions"].asMap("dimensions")
        dimensionsMap.keysExactly(SimilarityDimension.values().mapTo(linkedSetOf(), SimilarityDimension::reportKey), "dimensions")
        val dimensions = SimilarityDimension.values().associateWith { dimension ->
            dimensionsMap.decimal(dimension.reportKey)
        }
        val report = SimilarityReport(
            scorerVersion = root.string("scorerVersion"),
            ordinaryAabSha256 = root.string("ordinaryAabSha256"),
            hardenedAabSha256 = root.string("hardenedAabSha256"),
            ordinaryUniversalApkSha256 = root.nullableString("ordinaryUniversalApkSha256"),
            hardenedUniversalApkSha256 = root.nullableString("hardenedUniversalApkSha256"),
            ordinaryAabSize = root.long("ordinaryAabSize"),
            hardenedAabSize = root.long("hardenedAabSize"),
            ordinaryUniversalApkSize = root.nullableLong("ordinaryUniversalApkSize"),
            hardenedUniversalApkSize = root.nullableLong("hardenedUniversalApkSize"),
            dimensions = dimensions,
            topUnchangedCode = root.list("topUnchangedCode").map { item ->
                val evidence = item.asMap("code evidence")
                evidence.keysExactly(CODE_EVIDENCE_KEYS, "code evidence")
                CodeSimilarityEvidence(
                    evidence.string("ordinaryDescriptor"), evidence.string("hardenedDescriptor"),
                    evidence.integer("ordinaryInstructionCount"), evidence.decimal("similarity"),
                )
            },
            topUnchangedResources = root.list("topUnchangedResources").map { item ->
                val evidence = item.asMap("resource evidence")
                evidence.keysExactly(RESOURCE_EVIDENCE_KEYS, "resource evidence")
                ResourceSimilarityEvidence(
                    evidence.integer("resourceId"), evidence.string("qualifier"),
                    evidence.string("ordinaryEntryName"), evidence.long("ordinarySize"),
                )
            },
        )
        require(root.string("comparisonMode") == report.comparisonMode.name) { "comparison mode does not match provenance" }
        require(close(report.overallScore, root.decimal("overallScore"))) { "similarity report overall score mismatch" }
        require(close(report.growth, root.decimal("growth"))) { "similarity report growth mismatch" }
        return report
    }

    fun encodeMarkdown(report: SimilarityReport): String = buildString {
        append("# Owned Artifact Similarity\n\n")
        append("scorer: `").append(report.scorerVersion).append("`\n\n")
        append("mode: `").append(report.comparisonMode.name).append("`\n\n")
        append("| dimension | score | weight |\n| --- | ---: | ---: |\n")
        SimilarityDimension.values().forEach { dimension ->
            append("| ").append(dimension.reportKey).append(" | ")
                .append(number(report.dimensions.getValue(dimension))).append(" | ")
                .append(dimension.weight).append(" |\n")
        }
        append("\noverall: ").append(number(report.overallScore)).append("\n\n")
        append("## Provenance\n\n")
        append("- ordinary AAB: `").append(report.ordinaryAabSha256).append("` (size ")
            .append(report.ordinaryAabSize).append(")\n")
        append("- hardened AAB: `").append(report.hardenedAabSha256).append("` (size ")
            .append(report.hardenedAabSize).append(")\n")
        append("- ordinary universal APK: ").append(provenance(report.ordinaryUniversalApkSha256, report.ordinaryUniversalApkSize)).append("\n")
        append("- hardened universal APK: ").append(provenance(report.hardenedUniversalApkSha256, report.hardenedUniversalApkSize)).append("\n")
        append("\n## Unchanged Code\n\n")
        if (report.topUnchangedCode.isEmpty()) append("None\n") else report.topUnchangedCode.forEach { evidence ->
            append("- `").append(evidence.ordinaryDescriptor).append("` -> `")
                .append(evidence.hardenedDescriptor).append("` (")
                .append(evidence.ordinaryInstructionCount).append(" instructions)\n")
        }
        append("\n## Unchanged Resources\n\n")
        if (report.topUnchangedResources.isEmpty()) append("None\n") else report.topUnchangedResources.forEach { evidence ->
            append("- `").append(evidence.resourceId).append(':').append(evidence.qualifier).append("` ")
                .append(evidence.ordinaryEntryName).append(" (").append(evidence.ordinarySize).append(" bytes)\n")
        }
    }

    private fun provenance(hash: String?, size: Long?): String =
        if (hash == null) "not analyzed in AAB_ONLY mode" else "`$hash` (size $size)"

    private fun number(value: Double): String = value.toString()
    private fun close(left: Double, right: Double): Boolean = left.toBits() == right.toBits()
    private fun jsonOrNull(value: String?): String = value?.let(::json) ?: "null"
    private fun json(value: String): String = buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000c' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character.code < 0x20) append("\\u%04x".format(character.code)) else append(character)
            }
        }
        append('"')
    }

    private fun Any?.asMap(label: String): Map<*, *> = this as? Map<*, *> ?: throw IllegalArgumentException("$label must be an object")
    private fun Map<*, *>.keysExactly(expected: Set<String>, label: String) {
        require(keys == expected) { "$label keys must be exactly $expected" }
    }
    private fun Map<*, *>.string(key: String): String = this[key] as? String ?: throw IllegalArgumentException("$key must be a string")
    private fun Map<*, *>.nullableString(key: String): String? = when (val value = this[key]) {
        null -> null
        is String -> value
        else -> throw IllegalArgumentException("$key must be a string or null")
    }
    private fun Map<*, *>.long(key: String): Long = (this[key] as? Number)?.toLongExact(key)
        ?: throw IllegalArgumentException("$key must be an integer")
    private fun Map<*, *>.nullableLong(key: String): Long? = this[key]?.let { (it as? Number)?.toLongExact(key) }
        ?: if (this[key] == null) null else throw IllegalArgumentException("$key must be an integer or null")
    private fun Map<*, *>.integer(key: String): Int = long(key).also {
        require(it in Int.MIN_VALUE..Int.MAX_VALUE) { "$key must fit a signed 32-bit integer" }
    }.toInt()
    private fun Map<*, *>.decimal(key: String): Double = (this[key] as? Number)?.toDouble()?.also {
        require(it.isFinite()) { "$key must be finite" }
    } ?: throw IllegalArgumentException("$key must be a number")
    private fun Map<*, *>.list(key: String): List<*> = this[key] as? List<*> ?: throw IllegalArgumentException("$key must be an array")
    private fun Number.toLongExact(key: String): Long {
        val value = toLong()
        require(toDouble() == value.toDouble()) { "$key must be an integer" }
        return value
    }

    private val ROOT_KEYS = setOf(
        "schemaVersion", "scorerVersion", "comparisonMode", "ordinaryAabSha256", "hardenedAabSha256",
        "ordinaryUniversalApkSha256", "hardenedUniversalApkSha256", "ordinaryAabSize", "hardenedAabSize",
        "ordinaryUniversalApkSize", "hardenedUniversalApkSize", "dimensions", "overallScore", "growth",
        "topUnchangedCode", "topUnchangedResources",
    )
    private val CODE_EVIDENCE_KEYS = setOf("ordinaryDescriptor", "hardenedDescriptor", "ordinaryInstructionCount", "similarity")
    private val RESOURCE_EVIDENCE_KEYS = setOf("resourceId", "qualifier", "ordinaryEntryName", "ordinarySize")
}
