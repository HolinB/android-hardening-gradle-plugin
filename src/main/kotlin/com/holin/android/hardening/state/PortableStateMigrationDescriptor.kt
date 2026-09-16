package com.holin.android.hardening.state

import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.util.UUID

data class PortableStateMigrationDescriptor(
    val schemaVersion: Int,
    val projectKey: String,
    val variant: String,
    val state: PortableStateIdentityMigration,
    val baseline: PortableBaselineIdentityMigration?,
)

data class PortableStateIdentityMigration(
    val namespace: String,
    val applicationId: String,
    val fromContentDomain: String,
    val toContentDomain: String,
    val fromConfigurationSha256: String,
    val toConfigurationSha256: String,
    val lineageId: String,
    val generation: Long,
    val activePayloadSha256: String,
    val mappingSha256: String,
    val registrySha256: String,
    val seedSha256: String,
)

data class PortableBaselineIdentityMigration(
    val scorerVersion: String,
    val ownershipSha256: String,
    val fromConfigurationSha256: String,
    val toConfigurationSha256: String,
    val legacyPayloadSha256: String,
)

object PortableStateMigrationDescriptorCodec {
    fun encode(descriptor: PortableStateMigrationDescriptor): String {
        validate(descriptor)
        return buildString {
            append("{\"schemaVersion\":2")
            append(",\"projectKey\":").append(JsonOutput.toJson(descriptor.projectKey))
            append(",\"variant\":").append(JsonOutput.toJson(descriptor.variant))
            append(",\"state\":{")
            val state = descriptor.state
            append("\"namespace\":").append(JsonOutput.toJson(state.namespace))
            append(",\"applicationId\":").append(JsonOutput.toJson(state.applicationId))
            append(",\"fromContentDomain\":").append(JsonOutput.toJson(state.fromContentDomain))
            append(",\"toContentDomain\":").append(JsonOutput.toJson(state.toContentDomain))
            append(",\"fromConfigurationSha256\":").append(JsonOutput.toJson(state.fromConfigurationSha256))
            append(",\"toConfigurationSha256\":").append(JsonOutput.toJson(state.toConfigurationSha256))
            append(",\"lineageId\":").append(JsonOutput.toJson(state.lineageId))
            append(",\"generation\":").append(state.generation)
            append(",\"activePayloadSha256\":").append(JsonOutput.toJson(state.activePayloadSha256))
            append(",\"mappingSha256\":").append(JsonOutput.toJson(state.mappingSha256))
            append(",\"registrySha256\":").append(JsonOutput.toJson(state.registrySha256))
            append(",\"seedSha256\":").append(JsonOutput.toJson(state.seedSha256)).append('}')
            val baseline = descriptor.baseline
            if (baseline == null) {
                append(",\"baseline\":null}")
            } else {
                append(",\"baseline\":{")
                append("\"scorerVersion\":").append(JsonOutput.toJson(baseline.scorerVersion))
                append(",\"ownershipSha256\":").append(JsonOutput.toJson(baseline.ownershipSha256))
                append(",\"fromConfigurationSha256\":").append(JsonOutput.toJson(baseline.fromConfigurationSha256))
                append(",\"toConfigurationSha256\":").append(JsonOutput.toJson(baseline.toConfigurationSha256))
                append(",\"legacyPayloadSha256\":").append(JsonOutput.toJson(baseline.legacyPayloadSha256))
                append("}}")
            }
            append('\n')
        }
    }

    fun decode(text: String): PortableStateMigrationDescriptor {
        StrictJson.validateDocument(text)
        val root = JsonSlurper().parseText(text).objectMap("migration descriptor")
        root.keysExactly(ROOT_KEYS, "migration descriptor")
        val state = root["state"].objectMap("migration state")
        state.keysExactly(STATE_KEYS, "migration state")
        val baseline = root["baseline"]?.objectMap("migration baseline")
        baseline?.keysExactly(BASELINE_KEYS, "migration baseline")
        return PortableStateMigrationDescriptor(
            root.integer("schemaVersion"),
            root.string("projectKey"),
            root.string("variant"),
            PortableStateIdentityMigration(
                state.string("namespace"),
                state.string("applicationId"),
                state.string("fromContentDomain"),
                state.string("toContentDomain"),
                state.string("fromConfigurationSha256"),
                state.string("toConfigurationSha256"),
                state.string("lineageId"),
                state.long("generation"),
                state.string("activePayloadSha256"),
                state.string("mappingSha256"),
                state.string("registrySha256"),
                state.string("seedSha256"),
            ),
            baseline?.let { value ->
                PortableBaselineIdentityMigration(
                    value.string("scorerVersion"),
                    value.string("ownershipSha256"),
                    value.string("fromConfigurationSha256"),
                    value.string("toConfigurationSha256"),
                    value.string("legacyPayloadSha256"),
                )
            },
        ).also(::validate)
    }

    private fun validate(descriptor: PortableStateMigrationDescriptor) {
        require(descriptor.schemaVersion == 2) { "portable migration schemaVersion must be 2" }
        require(descriptor.projectKey.isNotBlank()) { "portable migration projectKey must not be blank" }
        require(descriptor.variant.isNotBlank()) { "portable migration variant must not be blank" }
        val state = descriptor.state
        require(state.namespace.isNotBlank()) { "portable migration namespace must not be blank" }
        require(state.applicationId.isNotBlank()) { "portable migration applicationId must not be blank" }
        require(
            state.fromContentDomain in setOf(
                CanonicalContentDomain.LEGACY_V1.id,
                CanonicalContentDomain.HOLIN_1_2.id,
                CanonicalContentDomain.HOLIN_1_3.id,
            ),
        ) {
            "portable migration fromContentDomain must identify a supported content domain"
        }
        require(state.toContentDomain == CanonicalContentDomain.HOLIN_1_3.id) {
            "portable migration toContentDomain must identify the 1.3.0 domain"
        }
        require(state.generation > 0) { "portable migration generation must be positive" }
        require(runCatching { UUID.fromString(state.lineageId) }.getOrNull()?.toString() == state.lineageId) {
            "portable migration lineageId must be a lowercase UUID"
        }
        val shaValues = mutableListOf(
            "state.fromConfigurationSha256" to state.fromConfigurationSha256,
            "state.toConfigurationSha256" to state.toConfigurationSha256,
            "state.activePayloadSha256" to state.activePayloadSha256,
            "state.mappingSha256" to state.mappingSha256,
            "state.registrySha256" to state.registrySha256,
            "state.seedSha256" to state.seedSha256,
        )
        descriptor.baseline?.let { baseline ->
            shaValues += "baseline.ownershipSha256" to baseline.ownershipSha256
            shaValues += "baseline.fromConfigurationSha256" to baseline.fromConfigurationSha256
            shaValues += "baseline.toConfigurationSha256" to baseline.toConfigurationSha256
            shaValues += "baseline.legacyPayloadSha256" to baseline.legacyPayloadSha256
        }
        shaValues.forEach { (label, value) ->
            require(SHA_256.matches(value)) { "portable migration $label must be lowercase SHA-256" }
        }
        require(state.fromConfigurationSha256 != state.toConfigurationSha256) {
            "portable migration state configuration identities must differ"
        }
        descriptor.baseline?.let { baseline ->
            require(baseline.fromConfigurationSha256 != baseline.toConfigurationSha256) {
                "portable migration baseline configuration identities must differ"
            }
            require(baseline.scorerVersion.isNotBlank()) {
                "portable migration baseline scorerVersion must not be blank"
            }
        }
    }

    private fun Any?.objectMap(label: String): Map<*, *> =
        this as? Map<*, *> ?: throw IllegalArgumentException("$label must be an object")

    private fun Map<*, *>.keysExactly(expected: Set<String>, label: String) {
        require(keys == expected) { "$label keys must be exactly $expected" }
    }

    private fun Map<*, *>.string(key: String): String =
        this[key] as? String ?: throw IllegalArgumentException("portable migration $key must be a string")

    private fun Map<*, *>.long(key: String): Long =
        (this[key] as? Number)?.toLong() ?: throw IllegalArgumentException("portable migration $key must be a number")

    private fun Map<*, *>.integer(key: String): Int {
        val value = long(key)
        require(value in Int.MIN_VALUE..Int.MAX_VALUE) { "portable migration $key must fit a signed 32-bit integer" }
        return value.toInt()
    }

    private val SHA_256 = Regex("[0-9a-f]{64}")
    private val ROOT_KEYS = setOf("schemaVersion", "projectKey", "variant", "state", "baseline")
    private val STATE_KEYS = setOf(
        "namespace", "applicationId", "fromContentDomain", "toContentDomain", "fromConfigurationSha256",
        "toConfigurationSha256", "lineageId",
        "generation", "activePayloadSha256", "mappingSha256", "registrySha256", "seedSha256",
    )
    private val BASELINE_KEYS = setOf(
        "scorerVersion", "ownershipSha256", "fromConfigurationSha256", "toConfigurationSha256",
        "legacyPayloadSha256",
    )
}
