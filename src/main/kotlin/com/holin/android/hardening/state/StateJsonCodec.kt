package com.holin.android.hardening.state

import groovy.json.JsonSlurper

internal class StateJsonCodec {
    fun encodeManifest(manifest: SnapshotManifest): String = buildString {
        append("{\"schemaVersion\":").append(manifest.schemaVersion)
        append(",\"identity\":{")
        val identity = manifest.identity
        append("\"schemaVersion\":").append(identity.schemaVersion)
        append(",\"projectKey\":").append(json(identity.projectKey))
        append(",\"variant\":").append(json(identity.variant))
        append(",\"namespace\":").append(json(identity.namespace))
        append(",\"applicationId\":").append(json(identity.applicationId))
        append(",\"configurationSha256\":").append(json(identity.configurationSha256))
        append(",\"lineageId\":").append(json(identity.lineageId))
        append(",\"generation\":").append(identity.generation)
        append(",\"seedHash\":").append(json(identity.seedHash))
        append(",\"payloadHashes\":{")
        identity.payloadHashes.toSortedMap().entries.forEachIndexed { index, entry ->
            if (index > 0) append(',')
            append(json(entry.key)).append(':').append(json(entry.value))
        }
        append("},\"lineageReset\":").append(identity.lineageReset)
        append(",\"derivationMode\":").append(json(identity.derivationMode.name))
        identity.fixedSeedSha256?.let { fixedSeedSha256 ->
            append(",\"fixedSeedSha256\":").append(json(fixedSeedSha256.sha("fixedSeedSha256")))
        }
        append('}')
        append(",\"lineageReason\":").append(json(manifest.lineageReason.name))
        append(",\"contentSaltSha256\":").append(json(manifest.contentSaltSha256))
        manifest.aabSha256?.let { aabSha256 ->
            append(",\"aabSha256\":").append(json(aabSha256.sha("aabSha256")))
        }
        append("}\n")
    }

    fun decodeManifest(json: String): SnapshotManifest {
        StrictJson.validate(json)
        val root = JsonSlurper().parseText(json).map("manifest")
        val legacyManifestKeys = setOf("schemaVersion", "identity", "lineageReason", "contentSaltSha256")
        require(root.keys == legacyManifestKeys || root.keys == legacyManifestKeys + "aabSha256") {
            "manifest keys must match the current or legacy schema"
        }
        val identityMap = root["identity"].map("identity")
        val legacyIdentityKeys = setOf(
            "schemaVersion", "projectKey", "variant", "namespace", "applicationId", "lineageId",
            "generation", "seedHash", "payloadHashes", "lineageReset",
        )
        val configuredIdentityKeys = legacyIdentityKeys + "configurationSha256"
        val reproducibleIdentityKeys = configuredIdentityKeys + "derivationMode"
        require(
            identityMap.keys == legacyIdentityKeys ||
                identityMap.keys == configuredIdentityKeys ||
                identityMap.keys == reproducibleIdentityKeys ||
                identityMap.keys == reproducibleIdentityKeys + "fixedSeedSha256",
        ) {
            "identity keys must match the current or legacy schema"
        }
        val payloads = identityMap["payloadHashes"].map("payloadHashes").entries.associate { (key, value) ->
            (key as? String ?: invalid("payload hash key must be a string")) to
                (value as? String ?: invalid("payload hash value must be a string")).sha("payload hash")
        }
        val schemaVersion = root.integer("schemaVersion")
        val identitySchemaVersion = identityMap.integer("schemaVersion")
        val derivationMode = if ("derivationMode" in identityMap) {
            enumValueOf<SeedDerivationMode>(identityMap.string("derivationMode"))
        } else {
            SeedDerivationMode.SECURE_RANDOM
        }
        val fixedSeedSha256 = if ("fixedSeedSha256" in identityMap) {
            identityMap.string("fixedSeedSha256").sha("fixedSeedSha256")
        } else {
            null
        }
        require((derivationMode == SeedDerivationMode.FIXED_SEED) == (fixedSeedSha256 != null)) {
            "fixed seed identity must be present exactly in fixed-seed mode"
        }
        return SnapshotManifest(
            schemaVersion,
            StateIdentity(
                identitySchemaVersion,
                identityMap.string("projectKey"),
                identityMap.string("variant"),
                identityMap.string("namespace"),
                identityMap.string("applicationId"),
                if ("configurationSha256" in identityMap) {
                    identityMap.string("configurationSha256").sha("configurationSha256")
                } else {
                    "0".repeat(64)
                },
                identityMap.string("lineageId"),
                identityMap.number("generation"),
                identityMap.string("seedHash").sha("seedHash"),
                payloads,
                identityMap.boolean("lineageReset"),
                derivationMode,
                fixedSeedSha256,
            ),
            enumValueOf(root.string("lineageReason")),
            root.string("contentSaltSha256").sha("contentSaltSha256"),
            if ("aabSha256" in root) root.string("aabSha256").sha("aabSha256") else null,
        ).also {
            require(
                it.schemaVersion in SUPPORTED_STATE_SCHEMAS &&
                    it.identity.schemaVersion == it.schemaVersion &&
                    (it.schemaVersion == LEGACY_STATE_SCHEMA_VERSION || "derivationMode" in identityMap),
            ) {
                "unsupported state schema"
            }
        }
    }

    fun encodeActive(pointer: ActivePointer): String =
        "{\"schemaVersion\":${pointer.schemaVersion},\"generation\":${pointer.generation}," +
            "\"snapshotId\":${json(pointer.snapshotId)},\"payloadSha256\":${json(pointer.payloadSha256)}}\n"

    fun decodeActive(json: String): ActivePointer {
        StrictJson.validate(json)
        val root = JsonSlurper().parseText(json).map("active pointer")
        root.keysExactly(setOf("schemaVersion", "generation", "snapshotId", "payloadSha256"), "active pointer")
        return ActivePointer(
            schemaVersion = root.integer("schemaVersion"),
            generation = root.number("generation"),
            snapshotId = root.string("snapshotId"),
            payloadSha256 = root.string("payloadSha256").sha("payloadSha256"),
        ).also {
            require(it.schemaVersion in SUPPORTED_STATE_SCHEMAS) { "unsupported active pointer schema ${it.schemaVersion}" }
            require(it.generation > 0) { "active generation must be positive" }
            require(it.snapshotId == "${it.generation}-${it.payloadSha256}") { "active snapshot id does not match generation and payload" }
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

    private companion object {
        val SUPPORTED_STATE_SCHEMAS = setOf(LEGACY_STATE_SCHEMA_VERSION, STATE_SCHEMA_VERSION)
    }
}

private fun Any?.map(label: String): Map<*, *> = this as? Map<*, *> ?: invalid("$label must be an object")
private fun Map<*, *>.keysExactly(expected: Set<String>, label: String) {
    require(keys == expected) { "$label keys must be exactly $expected" }
}
private fun Map<*, *>.string(key: String): String = this[key] as? String ?: invalid("$key must be a string")
private fun Map<*, *>.number(key: String): Long = (this[key] as? Number)?.toLong() ?: invalid("$key must be a number")
private fun Map<*, *>.integer(key: String): Int {
    val value = number(key)
    require(value in Int.MIN_VALUE..Int.MAX_VALUE) { "$key must fit a signed 32-bit integer" }
    return value.toInt()
}
private fun Map<*, *>.boolean(key: String): Boolean = this[key] as? Boolean ?: invalid("$key must be a boolean")
private fun String.sha(label: String): String {
    require(matches(Regex("[0-9a-f]{64}"))) { "$label must be a lowercase SHA-256" }
    return this
}
private fun invalid(message: String): Nothing = throw IllegalArgumentException(message)
