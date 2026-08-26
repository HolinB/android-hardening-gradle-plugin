package com.holin.android.hardening.naming

import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonSlurper

class RegistryCodec {
    fun encode(snapshot: RegistrySnapshot): String = buildString {
        append("{\"schemaVersion\":").append(snapshot.schemaVersion)
        append(",\"seedSha256\":").append(json(snapshot.seedSha256))
        append(",\"generation\":").append(snapshot.generation)
        append(",\"assignments\":[")
        snapshot.assignments.forEachIndexed { index, assignment ->
            if (index > 0) append(',')
            append("{\"originalIdentity\":").append(json(assignment.key.originalIdentity))
            append(",\"kind\":").append(json(assignment.key.kind.name))
            append(",\"descriptor\":").append(json(assignment.key.descriptor))
            append(",\"namespace\":").append(json(assignment.namespace))
            append(",\"alias\":").append(json(assignment.alias))
            append(",\"keyHash\":").append(json(assignment.keyHash)).append('}')
        }
        append("],\"tombstones\":[")
        snapshot.tombstones.forEachIndexed { index, tombstone ->
            if (index > 0) append(',')
            append("{\"namespace\":").append(json(tombstone.namespace))
            append(",\"kind\":").append(json(tombstone.kind.name))
            append(",\"alias\":").append(json(tombstone.alias))
            append(",\"keyHash\":").append(json(tombstone.keyHash))
            append(",\"retiredGeneration\":").append(tombstone.retiredGeneration).append('}')
        }
        append("]}\n")
    }

    fun decode(json: String): RegistrySnapshot {
        StrictJson.validate(json)
        val root = JsonSlurper().parseText(json).asMap("registry")
        root.requireKeys(setOf("schemaVersion", "seedSha256", "generation", "assignments", "tombstones"), "registry")
        return RegistrySnapshot(
            schemaVersion = root.integer("schemaVersion"),
            seedSha256 = root.string("seedSha256").requireSha("seedSha256"),
            generation = root.long("generation"),
            assignments = root.list("assignments").mapIndexed { index, raw ->
                val item = raw.asMap("assignments[$index]")
                item.requireKeys(setOf("originalIdentity", "kind", "descriptor", "namespace", "alias", "keyHash"), "assignments[$index]")
                RegistryAssignment(
                    key = RegistryKey(
                        item.string("originalIdentity"),
                        enumValueOf(item.string("kind")),
                        item.string("descriptor"),
                    ),
                    namespace = item.string("namespace"),
                    alias = item.string("alias"),
                    keyHash = item.string("keyHash").requireSha("keyHash"),
                )
            },
            tombstones = root.list("tombstones").mapIndexed { index, raw ->
                val item = raw.asMap("tombstones[$index]")
                item.requireKeys(setOf("namespace", "kind", "alias", "keyHash", "retiredGeneration"), "tombstones[$index]")
                AliasTombstone(
                    namespace = item.string("namespace"),
                    kind = enumValueOf(item.string("kind")),
                    alias = item.string("alias"),
                    keyHash = item.string("keyHash").requireSha("keyHash"),
                    retiredGeneration = item.long("retiredGeneration"),
                )
            },
        ).also {
            require(it.schemaVersion == 1) { "unsupported registry schema ${it.schemaVersion}" }
            require(it.generation > 0) { "registry generation must be positive" }
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

private fun Any?.asMap(label: String): Map<*, *> = this as? Map<*, *> ?: error("$label must be an object")
private fun Map<*, *>.string(key: String): String = this[key] as? String ?: error("$key must be a string")
private fun Map<*, *>.long(key: String): Long = (this[key] as? Number)?.toLong() ?: error("$key must be a number")
private fun Map<*, *>.integer(key: String): Int {
    val value = long(key)
    require(value in Int.MIN_VALUE..Int.MAX_VALUE) { "$key must fit a signed 32-bit integer" }
    return value.toInt()
}
private fun Map<*, *>.list(key: String): List<*> = this[key] as? List<*> ?: error("$key must be an array")
private fun Map<*, *>.requireKeys(expected: Set<String>, label: String) {
    require(keys == expected) { "$label keys must be exactly $expected" }
}
private fun String.requireSha(label: String): String {
    require(matches(Regex("[0-9a-f]{64}"))) { "$label must be a lowercase SHA-256" }
    return this
}
