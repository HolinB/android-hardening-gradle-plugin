package com.holin.android.hardening.verification

import com.holin.android.hardening.code.POTENTIAL_BEAN_FIELD_POLICY_VERSION
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonSlurper

enum class MappingVerificationStatus {
    PASS,
    FAIL,
}

data class MappingSymbolCounts(
    val classes: Int,
    val fields: Int,
    val methods: Int,
) {
    val total: Int = classes + fields + methods

    init {
        require(classes >= 0 && fields >= 0 && methods >= 0) { "mapping symbol counts must not be negative" }
    }

    companion object {
        fun from(mapping: ParsedR8Mapping): MappingSymbolCounts = MappingSymbolCounts(
            classes = mapping.symbols.keys.count { it.kind == SymbolKind.CLASS },
            fields = mapping.symbols.keys.count { it.kind == SymbolKind.FIELD },
            methods = mapping.symbols.keys.count { it.kind == SymbolKind.METHOD },
        )
    }
}

data class MappingVerificationReport(
    val variant: String,
    val status: MappingVerificationStatus,
    val r8Version: String,
    val previousMappingSha256: String,
    val activeMappingSha256: String = previousMappingSha256,
    val currentMappingSha256: String,
    val preparedMappingSha256: String,
    val hardenedAabSha256: String,
    val transformationReportSha256: String,
    val bundleVerificationReportSha256: String,
    val ordinaryAabSha256: String,
    val contentSaltSha256: String,
    val potentialBeanFieldManifestSha256: String,
    val potentialBeanFields: PotentialBeanFieldVerificationResult,
    val renamedOwnedClasses: Int,
    val renamedOwnedMethods: Int,
    val retiredLegacyFieldAssignmentCount: Int,
    val previousSymbols: MappingSymbolCounts,
    val currentSymbols: MappingSymbolCounts,
    val continuity: MappingContinuityResult,
    val retraceInputFrame: String?,
    val retracedFrames: List<String>,
    val retraceVerified: Boolean,
    val violations: List<String>,
    val fixedSeedProvided: Boolean = false,
    val fixedSeedHash: String? = null,
) {
    init {
        require(VARIANT.matches(variant)) { "mapping verification variant is invalid" }
        require(R8_VERSION.matches(r8Version)) { "mapping verification R8 version is invalid" }
        listOf(
            previousMappingSha256,
            activeMappingSha256,
            currentMappingSha256,
            preparedMappingSha256,
            hardenedAabSha256,
            transformationReportSha256,
            bundleVerificationReportSha256,
            ordinaryAabSha256,
            contentSaltSha256,
            potentialBeanFieldManifestSha256,
        ).forEach { hash -> require(SHA_256.matches(hash)) { "mapping verification contains an invalid SHA-256" } }
        require(renamedOwnedClasses >= 0 && renamedOwnedMethods >= 0) {
            "renamed owned symbol counts must not be negative"
        }
        require(retiredLegacyFieldAssignmentCount >= 0) {
            "retired legacy field assignment count must not be negative"
        }
        require(previousSymbols.total == continuity.previousCount) {
            "mapping continuity previous count differs from its symbol inventory"
        }
        require(continuity.applicableCount == continuity.stableCount + continuity.mismatches.size) {
            "mapping continuity applicable count is inconsistent"
        }
        require(continuity.noLongerPresentCount == continuity.previousCount - continuity.applicableCount) {
            "mapping continuity missing count is inconsistent"
        }
        requireFixedSeedIdentity(fixedSeedProvided, fixedSeedHash)
        when (status) {
            MappingVerificationStatus.PASS -> {
                require(violations.isEmpty() && continuity.mismatches.isEmpty() && retraceVerified) {
                    "passing mapping verification contains a failure"
                }
                require(potentialBeanFields.verified) {
                    "passing mapping verification contains potential Bean field violations"
                }
                require(potentialBeanFields.policyVersion == POTENTIAL_BEAN_FIELD_POLICY_VERSION) {
                    "passing verification has a different potential Bean field policy"
                }
                require(potentialBeanFields.moduleFieldCounts.isNotEmpty()) {
                    "passing verification has an empty potential Bean module scope"
                }
                require(renamedOwnedClasses > 0 && renamedOwnedMethods > 0) {
                    "passing verification must contain renamed owned classes and methods"
                }
                require(retraceInputFrame != null && retracedFrames.isNotEmpty()) {
                    "passing mapping verification must contain Retrace evidence"
                }
            }
            MappingVerificationStatus.FAIL -> require(violations.isNotEmpty()) {
                "failed mapping verification must explain its failure"
            }
        }
    }

    private companion object {
        val VARIANT = Regex("[A-Za-z][A-Za-z0-9]*")
        val R8_VERSION = Regex("[0-9]+\\.[0-9]+\\.[0-9]+")
        val SHA_256 = Regex("[0-9a-f]{64}")
    }
}

data class PassingMappingVerificationProvenance(
    val variant: String,
    val r8Version: String,
    val previousMappingSha256: String,
    val activeMappingSha256: String,
    val currentMappingSha256: String,
    val preparedMappingSha256: String,
    val hardenedAabSha256: String,
    val transformationReportSha256: String,
    val bundleVerificationReportSha256: String,
    val ordinaryAabSha256: String,
    val contentSaltSha256: String,
    val potentialBeanFieldManifestSha256: String,
    val retiredLegacyFieldAssignmentCount: Int,
    val fixedSeedProvided: Boolean,
    val fixedSeedHash: String?,
) {
    init {
        requireFixedSeedIdentity(fixedSeedProvided, fixedSeedHash)
    }
}

object MappingVerificationReportCodec {
    fun encode(report: MappingVerificationReport): String = buildString {
        append("{\"schemaVersion\":2")
        append(",\"variant\":").append(json(report.variant))
        append(",\"status\":").append(json(report.status.name))
        append(",\"r8Version\":").append(json(report.r8Version))
        append(",\"previousMappingSha256\":").append(json(report.previousMappingSha256))
        append(",\"activeMappingSha256\":").append(json(report.activeMappingSha256))
        append(",\"currentMappingSha256\":").append(json(report.currentMappingSha256))
        append(",\"preparedMappingSha256\":").append(json(report.preparedMappingSha256))
        append(",\"hardenedAabSha256\":").append(json(report.hardenedAabSha256))
        append(",\"transformationReportSha256\":").append(json(report.transformationReportSha256))
        append(",\"bundleVerificationReportSha256\":").append(json(report.bundleVerificationReportSha256))
        append(",\"ordinaryAabSha256\":").append(json(report.ordinaryAabSha256))
        append(",\"contentSaltSha256\":").append(json(report.contentSaltSha256))
        append(",\"potentialBeanFieldManifestSha256\":").append(json(report.potentialBeanFieldManifestSha256))
        append(",\"potentialBeanFields\":")
        appendPotentialBeanFields(report.potentialBeanFields)
        append(",\"renamedOwnedClasses\":").append(report.renamedOwnedClasses)
        append(",\"renamedOwnedMethods\":").append(report.renamedOwnedMethods)
        append(",\"retiredLegacyFieldAssignmentCount\":").append(report.retiredLegacyFieldAssignmentCount)
        append(",\"previousSymbols\":")
        appendCounts(report.previousSymbols)
        append(",\"currentSymbols\":")
        appendCounts(report.currentSymbols)
        append(",\"continuity\":{")
        append("\"previousCount\":").append(report.continuity.previousCount)
        append(",\"applicableCount\":").append(report.continuity.applicableCount)
        append(",\"stableCount\":").append(report.continuity.stableCount)
        append(",\"noLongerPresentCount\":").append(report.continuity.noLongerPresentCount)
        append(",\"mismatches\":[")
        report.continuity.mismatches.sortedWith(MISMATCH_ORDER).forEachIndexed { index, mismatch ->
            if (index > 0) append(',')
            append("{\"kind\":").append(json(mismatch.key.kind.name))
            append(",\"originalOwner\":").append(json(mismatch.key.originalOwner))
            append(",\"originalName\":").append(json(mismatch.key.originalName))
            append(",\"jvmDescriptor\":").append(json(mismatch.key.jvmDescriptor))
            append(",\"previousObfuscatedNames\":")
            appendStrings(mismatch.previousObfuscatedNames.sorted())
            append(",\"currentObfuscatedNames\":")
            appendStrings(mismatch.currentObfuscatedNames.sorted())
            append('}')
        }
        append("]}")
        append(",\"retraceInputFrame\":").append(report.retraceInputFrame?.let(::json) ?: "null")
        append(",\"retracedFrames\":")
        appendStrings(report.retracedFrames)
        append(",\"retraceVerified\":").append(report.retraceVerified)
        append(",\"violations\":")
        appendStrings(report.violations.sorted())
        append(",\"fixedSeedProvided\":").append(report.fixedSeedProvided)
        append(",\"fixedSeedHash\":").append(report.fixedSeedHash?.let(::json) ?: "null")
        append("}\n")
    }

    fun decodePassingProvenance(json: String): PassingMappingVerificationProvenance {
        StrictJson.validate(json)
        val root = JsonSlurper().parseText(json).reportMap("mapping verification report")
        return decodePassingProvenance(
            json,
            root.reportSha256("potentialBeanFieldManifestSha256"),
            root.reportNonNegativeInt("retiredLegacyFieldAssignmentCount"),
        )
    }

    fun decodePassingProvenance(
        json: String,
        expectedPotentialBeanFieldManifestSha256: String,
        expectedRetiredLegacyFieldAssignmentCount: Int,
    ): PassingMappingVerificationProvenance {
        require(REPORT_SHA_256.matches(expectedPotentialBeanFieldManifestSha256)) {
            "expected potential Bean field manifest hash must be a lowercase SHA-256"
        }
        require(expectedRetiredLegacyFieldAssignmentCount >= 0) {
            "expected retired legacy field assignment count must not be negative"
        }
        StrictJson.validate(json)
        val root = JsonSlurper().parseText(json).reportMap("mapping verification report")
        root.requireExactKeys(REPORT_KEYS, "mapping verification report")
        require(root.reportInt("schemaVersion") == 2) {
            "passing mapping verification report must use schema 2"
        }
        val variant = root.reportString("variant")
        require(REPORT_VARIANT.matches(variant)) { "mapping verification variant is invalid" }
        val r8Version = root.reportString("r8Version")
        require(REPORT_R8_VERSION.matches(r8Version)) { "mapping verification R8 version is invalid" }
        REPORT_HASH_KEYS.forEach(root::reportSha256)
        require(root.reportString("status") == MappingVerificationStatus.PASS.name) {
            "mapping verification report did not pass"
        }
        val continuity = root["continuity"].reportMap("continuity")
        continuity.requireExactKeys(CONTINUITY_KEYS, "continuity")
        val previousSymbols = root["previousSymbols"].reportCounts("previousSymbols")
        root["currentSymbols"].reportCounts("currentSymbols")
        val previousCount = continuity.reportNonNegativeInt("previousCount")
        val applicableCount = continuity.reportNonNegativeInt("applicableCount")
        val stableCount = continuity.reportNonNegativeInt("stableCount")
        val noLongerPresentCount = continuity.reportNonNegativeInt("noLongerPresentCount")
        require(previousCount == previousSymbols && applicableCount == stableCount) {
            "passing mapping verification continuity counts are inconsistent"
        }
        require(noLongerPresentCount == previousCount - applicableCount) {
            "passing mapping verification missing count is inconsistent"
        }
        require(continuity["mismatches"].reportList("continuity mismatches").isEmpty()) {
            "passing mapping verification report contains continuity mismatches"
        }
        require(root.reportBoolean("retraceVerified")) {
            "mapping verification report did not pass Retrace"
        }
        require(root["retraceInputFrame"] is String) {
            "passing mapping verification report must contain a Retrace input frame"
        }
        require(root["retracedFrames"].reportStringList("retracedFrames").isNotEmpty()) {
            "passing mapping verification report must contain retraced frames"
        }
        require(root["violations"].reportStringList("violations").isEmpty()) {
            "passing mapping verification report contains violations"
        }
        val fieldResult = root["potentialBeanFields"].reportMap("potentialBeanFields")
        fieldResult.requireExactKeys(POTENTIAL_BEAN_FIELD_KEYS, "potentialBeanFields")
        require(fieldResult.reportBoolean("verified")) {
            "mapping verification report did not verify potential Bean fields"
        }
        require(fieldResult["violations"].reportStringList("potentialBeanFields.violations").isEmpty()) {
            "passing mapping verification report contains potential Bean field violations"
        }
        val moduleCounts = fieldResult["moduleFieldCounts"].reportMap("potentialBeanFields.moduleFieldCounts")
        val protectedCount = fieldResult.reportNonNegativeInt("protectedFieldCount")
        require(
            moduleCounts.values.sumOf { count ->
                count.reportInt("module field count").also { value ->
                    require(value >= 0) { "module field count must not be negative" }
                }
            } == protectedCount,
        ) {
            "potential Bean module field counts differ from the protected field count"
        }
        val survivingOwnerCount = fieldResult.reportNonNegativeInt("survivingOwnerCount")
        val shrunkOwnerCount = fieldResult.reportNonNegativeInt("shrunkOwnerCount")
        require(survivingOwnerCount + shrunkOwnerCount <= protectedCount) {
            "potential Bean owner counts exceed the protected field count"
        }
        val policyVersion = fieldResult.reportInt("policyVersion")
        require(policyVersion > 0) { "potential Bean field policy version must be positive" }
        val renamedOwnedClasses = root.reportNonNegativeInt("renamedOwnedClasses")
        val renamedOwnedMethods = root.reportNonNegativeInt("renamedOwnedMethods")
        require(policyVersion == POTENTIAL_BEAN_FIELD_POLICY_VERSION) {
            "passing verification has a different potential Bean field policy"
        }
        require(moduleCounts.isNotEmpty()) {
            "passing verification has an empty potential Bean module scope"
        }
        require(renamedOwnedClasses > 0 && renamedOwnedMethods > 0) {
            "passing verification must contain renamed owned classes and methods"
        }
        val potentialBeanFieldManifestSha256 = root.reportSha256("potentialBeanFieldManifestSha256")
        require(potentialBeanFieldManifestSha256 == expectedPotentialBeanFieldManifestSha256) {
            "mapping verification report identifies a different potential Bean field manifest"
        }
        val retiredLegacyFieldAssignmentCount = root.reportNonNegativeInt("retiredLegacyFieldAssignmentCount")
        require(retiredLegacyFieldAssignmentCount == expectedRetiredLegacyFieldAssignmentCount) {
            "mapping verification report contains a different retired legacy field assignment count"
        }
        val fixedSeedProvided = root.reportBoolean("fixedSeedProvided")
        val fixedSeedHash = root.reportNullableString("fixedSeedHash")
        requireFixedSeedIdentity(fixedSeedProvided, fixedSeedHash)
        return PassingMappingVerificationProvenance(
            variant,
            r8Version,
            root.reportSha256("previousMappingSha256"),
            root.reportSha256("activeMappingSha256"),
            root.reportSha256("currentMappingSha256"),
            root.reportSha256("preparedMappingSha256"),
            root.reportSha256("hardenedAabSha256"),
            root.reportSha256("transformationReportSha256"),
            root.reportSha256("bundleVerificationReportSha256"),
            root.reportSha256("ordinaryAabSha256"),
            root.reportSha256("contentSaltSha256"),
            potentialBeanFieldManifestSha256,
            retiredLegacyFieldAssignmentCount,
            fixedSeedProvided,
            fixedSeedHash,
        ).also { provenance ->
            require(provenance.currentMappingSha256 == provenance.preparedMappingSha256) {
                "passing mapping verification report contains different current and prepared mappings"
            }
        }
    }

    private fun StringBuilder.appendCounts(counts: MappingSymbolCounts) {
        append("{\"classes\":").append(counts.classes)
        append(",\"fields\":").append(counts.fields)
        append(",\"methods\":").append(counts.methods)
        append(",\"total\":").append(counts.total).append('}')
    }

    private fun StringBuilder.appendPotentialBeanFields(result: PotentialBeanFieldVerificationResult) {
        append("{\"policyVersion\":").append(result.policyVersion)
        append(",\"moduleFieldCounts\":{")
        result.moduleFieldCounts.toSortedMap().entries.forEachIndexed { index, (module, count) ->
            if (index > 0) append(',')
            append(json(module)).append(':').append(count)
        }
        append("},\"protectedFieldCount\":").append(result.protectedFieldCount)
        append(",\"survivingOwnerCount\":").append(result.survivingOwnerCount)
        append(",\"shrunkOwnerCount\":").append(result.shrunkOwnerCount)
        append(",\"verified\":").append(result.verified)
        append(",\"violations\":")
        appendStrings(result.violations.sorted())
        append('}')
    }

    private fun StringBuilder.appendStrings(values: List<String>) {
        append('[')
        values.forEachIndexed { index, value ->
            if (index > 0) append(',')
            append(json(value))
        }
        append(']')
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
                else -> if (character.code < 0x20) {
                    append("\\u").append(character.code.toString(16).padStart(4, '0'))
                } else {
                    append(character)
                }
            }
        }
        append('"')
    }

    private val MISMATCH_ORDER: Comparator<MappingContinuityMismatch> = Comparator { first, second ->
        MappingContinuityVerifier.SYMBOL_ORDER.compare(first.key, second.key)
    }
    private val REPORT_KEYS = setOf(
        "schemaVersion", "variant", "status", "r8Version", "previousMappingSha256", "activeMappingSha256", "currentMappingSha256",
        "preparedMappingSha256", "hardenedAabSha256", "transformationReportSha256",
        "bundleVerificationReportSha256", "ordinaryAabSha256", "contentSaltSha256",
        "potentialBeanFieldManifestSha256", "potentialBeanFields", "renamedOwnedClasses", "renamedOwnedMethods",
        "retiredLegacyFieldAssignmentCount", "previousSymbols", "currentSymbols", "continuity", "retraceInputFrame",
        "retracedFrames", "retraceVerified", "violations", "fixedSeedProvided", "fixedSeedHash",
    )
    private val POTENTIAL_BEAN_FIELD_KEYS = setOf(
        "policyVersion", "moduleFieldCounts", "protectedFieldCount", "survivingOwnerCount", "shrunkOwnerCount",
        "verified", "violations",
    )
    private val CONTINUITY_KEYS = setOf(
        "previousCount", "applicableCount", "stableCount", "noLongerPresentCount", "mismatches",
    )
    private val REPORT_HASH_KEYS = setOf(
        "previousMappingSha256", "activeMappingSha256", "currentMappingSha256", "preparedMappingSha256", "hardenedAabSha256",
        "transformationReportSha256", "bundleVerificationReportSha256", "ordinaryAabSha256", "contentSaltSha256",
        "potentialBeanFieldManifestSha256",
    )
}

private fun Any?.reportMap(label: String): Map<*, *> = this as? Map<*, *>
    ?: throw IllegalArgumentException("$label must be an object")

private fun Any?.reportList(label: String): List<*> = this as? List<*>
    ?: throw IllegalArgumentException("$label must be an array")

private fun Any?.reportStringList(label: String): List<String> = reportList(label).map { value ->
    value as? String ?: throw IllegalArgumentException("$label values must be strings")
}

private fun Map<*, *>.reportString(key: String): String = this[key] as? String
    ?: throw IllegalArgumentException("$key must be a string")

private fun Map<*, *>.reportNullableString(key: String): String? = when (val value = this[key]) {
    null -> null
    is String -> value
    else -> throw IllegalArgumentException("$key must be a string or null")
}

private fun Map<*, *>.reportBoolean(key: String): Boolean = this[key] as? Boolean
    ?: throw IllegalArgumentException("$key must be a boolean")

private fun Map<*, *>.reportInt(key: String): Int = this[key].reportInt(key)

private fun Any?.reportInt(label: String): Int {
    val number = this as? Number ?: throw IllegalArgumentException("$label must be a number")
    val value = number.toLong()
    require(value in Int.MIN_VALUE..Int.MAX_VALUE && number.toDouble() == value.toDouble()) {
        "$label must be a signed 32-bit integer"
    }
    return value.toInt()
}

private fun Map<*, *>.reportNonNegativeInt(key: String): Int = reportInt(key).also { value ->
    require(value >= 0) { "$key must not be negative" }
}

private fun Map<*, *>.reportSha256(key: String): String = reportString(key).also { value ->
    require(REPORT_SHA_256.matches(value)) { "$key must be a lowercase SHA-256" }
}

private fun Any?.reportCounts(label: String): Int {
    val counts = reportMap(label)
    counts.requireExactKeys(setOf("classes", "fields", "methods", "total"), label)
    val classes = counts.reportNonNegativeInt("classes")
    val fields = counts.reportNonNegativeInt("fields")
    val methods = counts.reportNonNegativeInt("methods")
    val total = counts.reportNonNegativeInt("total")
    require(total == classes + fields + methods) { "$label total is inconsistent" }
    return total
}

private fun Map<*, *>.requireExactKeys(expected: Set<String>, label: String) {
    require(keys == expected) { "$label keys must be exactly $expected" }
}

private fun requireFixedSeedIdentity(fixedSeedProvided: Boolean, fixedSeedHash: String?) {
    require(fixedSeedProvided == (fixedSeedHash != null)) {
        "fixed seed hash must be present exactly when fixedSeedProvided is true"
    }
    fixedSeedHash?.let { hash ->
        require(REPORT_SHA_256.matches(hash)) { "fixedSeedHash must be a lowercase SHA-256" }
    }
}

private val REPORT_SHA_256 = Regex("[0-9a-f]{64}")
private val REPORT_VARIANT = Regex("[A-Za-z][A-Za-z0-9]*")
private val REPORT_R8_VERSION = Regex("[0-9]+\\.[0-9]+\\.[0-9]+")
