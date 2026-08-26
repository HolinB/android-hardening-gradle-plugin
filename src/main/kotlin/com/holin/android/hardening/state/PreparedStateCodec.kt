package com.holin.android.hardening.state

import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64

object PreparedStateCodec {
    fun write(path: Path, state: PreparedState) {
        val values = linkedMapOf(
            "schemaVersion" to STATE_SCHEMA_VERSION.toString(),
            "root" to encode(state.root.toAbsolutePath().normalize().toString()),
            "preparedDirectory" to encode(state.preparedDirectory.toAbsolutePath().normalize().toString()),
            "projectKey" to encode(state.coordinates.projectKey),
            "variant" to encode(state.coordinates.variant),
            "namespace" to encode(state.coordinates.namespace),
            "applicationId" to encode(state.coordinates.applicationId),
            "configurationSha256" to state.coordinates.configurationSha256,
            "lineageId" to encode(state.identity.lineageId),
            "generation" to state.identity.generation.toString(),
            "seedHash" to state.identity.seedHash,
            "mappingHash" to state.identity.payloadHashes.getValue("mapping.txt"),
            "registryHash" to state.identity.payloadHashes.getValue("registry.json"),
            "seedPayloadHash" to state.identity.payloadHashes.getValue("seed.bin"),
            "lineageReset" to state.identity.lineageReset.toString(),
            "derivationMode" to state.identity.derivationMode.name,
            "fixedSeedSha256" to state.identity.fixedSeedSha256.orEmpty(),
            "reason" to state.reason.name,
            "expectedGeneration" to state.expectedGeneration.toString(),
            "expectedPayloadSha256" to (state.expectedPayloadSha256 ?: ""),
            "contentSaltSha256" to state.contentSaltSha256,
            "quarantinedDirectory" to encode(state.quarantinedDirectory?.toAbsolutePath()?.normalize()?.toString().orEmpty()),
            "keepHistory" to state.keepHistory.toString(),
        )
        Files.writeString(path, values.entries.joinToString("\n", postfix = "\n") { (key, value) -> "$key=$value" })
    }

    fun read(path: Path): PreparedState {
        val values = linkedMapOf<String, String>()
        Files.readAllLines(path).filter(String::isNotBlank).forEach { line ->
            val separator = line.indexOf('=')
            require(separator > 0) { "invalid prepared state line" }
            val key = line.substring(0, separator)
            require(values.put(key, line.substring(separator + 1)) == null) { "duplicate prepared state key: $key" }
        }
        val expectedKeys = setOf(
            "schemaVersion", "root", "preparedDirectory", "projectKey", "variant", "namespace", "applicationId",
            "configurationSha256",
            "lineageId", "generation", "seedHash", "mappingHash", "registryHash", "seedPayloadHash",
            "lineageReset", "derivationMode", "fixedSeedSha256", "reason", "expectedGeneration",
            "expectedPayloadSha256", "contentSaltSha256",
            "quarantinedDirectory", "keepHistory",
        )
        require(values.keys == expectedKeys) { "prepared state keys must be exactly $expectedKeys" }
        require(values.getValue("schemaVersion").toInt() == STATE_SCHEMA_VERSION) { "unsupported prepared state schema" }
        val coordinates = StateCoordinates(
            decode(values.getValue("projectKey")),
            decode(values.getValue("variant")),
            decode(values.getValue("namespace")),
            decode(values.getValue("applicationId")),
            values.getValue("configurationSha256").requireSha("configurationSha256"),
        )
        val identity = StateIdentity(
            STATE_SCHEMA_VERSION,
            coordinates.projectKey,
            coordinates.variant,
            coordinates.namespace,
            coordinates.applicationId,
            coordinates.configurationSha256,
            decode(values.getValue("lineageId")),
            values.getValue("generation").toLong(),
            values.getValue("seedHash").requireSha("seedHash"),
            linkedMapOf(
                "mapping.txt" to values.getValue("mappingHash").requireSha("mappingHash"),
                "registry.json" to values.getValue("registryHash").requireSha("registryHash"),
                "seed.bin" to values.getValue("seedPayloadHash").requireSha("seedPayloadHash"),
            ),
            values.getValue("lineageReset").toBooleanStrict(),
            enumValueOf(values.getValue("derivationMode")),
            values.getValue("fixedSeedSha256").takeIf(String::isNotEmpty)?.requireSha("fixedSeedSha256"),
        )
        val quarantine = decode(values.getValue("quarantinedDirectory")).takeIf(String::isNotEmpty)?.let(Path::of)
        return PreparedState(
            Path.of(decode(values.getValue("root"))),
            coordinates,
            Path.of(decode(values.getValue("preparedDirectory"))),
            identity,
            enumValueOf(values.getValue("reason")),
            values.getValue("expectedGeneration").toLong(),
            values.getValue("expectedPayloadSha256").takeIf(String::isNotEmpty)?.requireSha("expectedPayloadSha256"),
            values.getValue("contentSaltSha256").requireSha("contentSaltSha256"),
            quarantine,
            values.getValue("keepHistory").toBooleanStrict(),
        )
    }

    private fun encode(value: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray(Charsets.UTF_8))
    private fun decode(value: String): String = if (value.isEmpty()) "" else Base64.getUrlDecoder().decode(value).toString(Charsets.UTF_8)
    private fun String.requireSha(label: String): String {
        require(matches(Regex("[0-9a-f]{64}"))) { "$label must be a lowercase SHA-256" }
        return this
    }
}
