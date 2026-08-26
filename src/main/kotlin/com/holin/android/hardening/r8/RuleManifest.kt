package com.holin.android.hardening.r8

data class HardeningRulesFilterResult(
    val effectiveRules: String,
    val manifest: HardeningRuleManifest,
)

data class HardeningRuleManifest(
    val schemaVersion: Int,
    val sourceSha256: String,
    val normalizedSourceSha256: String,
    val outputSha256: String,
    val normalizedOutputSha256: String,
    val decisions: List<RuleDecision>,
)

data class RuleDecision(
    val ordinal: Int,
    val directive: String?,
    val action: RuleDecisionAction,
    val reason: RuleDecisionReason,
    val sourceSha256: String,
    val normalizedSha256: String,
)

enum class RuleDecisionAction { PRESERVE, REMOVE }

enum class RuleDecisionReason {
    UNKNOWN_RULE,
    PRESERVED_EXACT_RULE,
    BROAD_ANDROIDX,
    BROAD_GOOGLE,
    BROAD_OWNED_PACKAGE,
    BROAD_WILDCARD_SUBCLASS,
    BROAD_SERIALIZABLE_CLASS_NAMES,
    BROAD_GSON_IMPLEMENTATION_CLASS_NAMES,
    BROAD_PARCELABLE_CLASS_NAMES,
    GLOBAL_FIELDS,
    GLOBAL_VIEW_OR_COMPONENT,
    BROAD_R_OR_BINDING,
}

object HardeningRuleManifestCodec {
    fun encode(
        variantName: String,
        sourceFile: String,
        generatedFile: String,
        sourceWasReplaced: Boolean,
        sourceOccurrenceCount: Int,
        manifest: HardeningRuleManifest,
    ): String {
        require(sourceOccurrenceCount >= 0) { "source ProGuard occurrence count cannot be negative" }
        require(sourceWasReplaced == (sourceOccurrenceCount > 0)) {
            "source ProGuard replacement flag does not match its occurrence count"
        }
        val preservedCount = manifest.decisions.count { it.action == RuleDecisionAction.PRESERVE }
        val removedCount = manifest.decisions.count { it.action == RuleDecisionAction.REMOVE }
        return buildString {
            append("{\"schemaVersion\":").append(manifest.schemaVersion)
            append(",\"variantName\":").append(json(variantName))
            append(",\"sourceFile\":").append(json(sourceFile))
            append(",\"generatedFile\":").append(json(generatedFile))
            append(",\"sourceWasReplaced\":").append(sourceWasReplaced)
            append(",\"sourceOccurrenceCount\":").append(sourceOccurrenceCount)
            append(",\"sourceSha256\":").append(json(manifest.sourceSha256))
            append(",\"normalizedSourceSha256\":").append(json(manifest.normalizedSourceSha256))
            append(",\"outputSha256\":").append(json(manifest.outputSha256))
            append(",\"normalizedOutputSha256\":").append(json(manifest.normalizedOutputSha256))
            append(",\"preservedRuleCount\":").append(preservedCount)
            append(",\"removedRuleCount\":").append(removedCount)
            append(",\"decisions\":[")
            manifest.decisions.forEachIndexed { index, decision ->
                if (index > 0) append(',')
                append("{\"ordinal\":").append(decision.ordinal)
                append(",\"directive\":")
                decision.directive?.let { append(json(it)) } ?: append("null")
                append(",\"action\":").append(json(decision.action.name))
                append(",\"reason\":").append(json(decision.reason.name))
                append(",\"sourceSha256\":").append(json(decision.sourceSha256))
                append(",\"normalizedSha256\":").append(json(decision.normalizedSha256))
                append('}')
            }
            append("]}\n")
        }
    }

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
}
