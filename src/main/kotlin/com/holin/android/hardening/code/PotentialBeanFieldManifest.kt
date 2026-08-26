package com.holin.android.hardening.code

import com.holin.android.hardening.state.Sha256
import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonSlurper
import java.util.ArrayList
import java.util.Collections
import java.util.LinkedHashSet
import org.objectweb.asm.Opcodes

class PotentialBeanFieldManifest(
    val schemaVersion: Int,
    val policyVersion: Int,
    val variant: String,
    val generation: Long,
    val configurationSha256: String,
    val inventorySha256: String,
    ownedModules: Set<String>,
    fields: Collection<PotentialBeanField>,
    val retiredLegacyFieldAssignmentCount: Int,
) {
    val ownedModules: Set<String> = Collections.unmodifiableSet(LinkedHashSet(ownedModules.sorted()))
    val fields: List<PotentialBeanField> = Collections.unmodifiableList(
        ArrayList(fields.sortedWith(POTENTIAL_BEAN_FIELD_ORDER)),
    )

    init {
        require(schemaVersion == 1) { "unsupported potential Bean field manifest schema $schemaVersion" }
        require(policyVersion == POTENTIAL_BEAN_FIELD_POLICY_VERSION) {
            "unsupported potential Bean field policy $policyVersion"
        }
        require(variant.isNotBlank()) { "potential Bean field manifest variant must not be blank" }
        require(generation > 0) { "potential Bean field manifest generation must be positive" }
        require(CONFIGURATION_HASH.matches(configurationSha256)) {
            "configurationSha256 must be a lowercase SHA-256"
        }
        require(CONFIGURATION_HASH.matches(inventorySha256)) { "inventorySha256 must be a lowercase SHA-256" }
        require(retiredLegacyFieldAssignmentCount >= 0) {
            "retired legacy field assignment count must not be negative"
        }
        require(this.ownedModules.isNotEmpty()) { "potential Bean field manifest owned modules must not be empty" }
        require(this.fields.map(PotentialBeanField::key).distinct().size == this.fields.size) {
            "potential Bean field manifest contains duplicate symbol keys"
        }
        this.fields.forEach(::validatePotentialBeanField)
    }

    override fun equals(other: Any?): Boolean = other is PotentialBeanFieldManifest &&
        schemaVersion == other.schemaVersion && policyVersion == other.policyVersion &&
        variant == other.variant && generation == other.generation &&
        configurationSha256 == other.configurationSha256 && inventorySha256 == other.inventorySha256 &&
        ownedModules == other.ownedModules && fields == other.fields &&
        retiredLegacyFieldAssignmentCount == other.retiredLegacyFieldAssignmentCount

    override fun hashCode(): Int = listOf(
        schemaVersion,
        policyVersion,
        variant,
        generation,
        configurationSha256,
        inventorySha256,
        ownedModules,
        fields,
        retiredLegacyFieldAssignmentCount,
    ).hashCode()

    override fun toString(): String = "PotentialBeanFieldManifest(schemaVersion=$schemaVersion, " +
        "policyVersion=$policyVersion, variant=$variant, generation=$generation, " +
        "configurationSha256=$configurationSha256, inventorySha256=$inventorySha256, " +
        "ownedModules=$ownedModules, fields=$fields, " +
        "retiredLegacyFieldAssignmentCount=$retiredLegacyFieldAssignmentCount)"
}

class PotentialBeanFieldManifestCodec {
    fun encode(manifest: PotentialBeanFieldManifest): String = buildString {
        append("{\"schemaVersion\":").append(manifest.schemaVersion)
        append(",\"policyVersion\":").append(manifest.policyVersion)
        append(",\"variant\":").append(fieldJsonString(manifest.variant))
        append(",\"generation\":").append(manifest.generation)
        append(",\"configurationSha256\":").append(fieldJsonString(manifest.configurationSha256))
        append(",\"inventorySha256\":").append(fieldJsonString(manifest.inventorySha256))
        append(",\"ownedModules\":[")
        manifest.ownedModules.forEachIndexed { index, module ->
            if (index > 0) append(',')
            append(fieldJsonString(module))
        }
        append("],\"fields\":")
        append(canonicalFieldRecords(manifest.fields))
        append(",\"retiredLegacyFieldAssignmentCount\":")
            .append(manifest.retiredLegacyFieldAssignmentCount)
        append("}\n")
    }

    fun decode(json: String): PotentialBeanFieldManifest {
        require(json.toByteArray(Charsets.UTF_8).size <= MAX_JSON_BYTES) {
            "potential Bean field manifest exceeds the 16 MiB input limit"
        }
        StrictJson.validate(json)
        val root = JsonSlurper().parseText(json).fieldManifestMap("manifest")
        root.fieldExactKeys(ROOT_KEYS, "manifest")
        val ownedModules = root.fieldStringList("ownedModules")
        require(ownedModules.distinct().size == ownedModules.size) {
            "potential Bean field manifest contains duplicate owned modules"
        }
        val fields = root.fieldList("fields").mapIndexed { index, value ->
            decodeField(value, "fields[$index]")
        }
        val declaredInventorySha256 = root.fieldString("inventorySha256")
        require(declaredInventorySha256 == inventorySha256(fields)) {
            "potential Bean field manifest inventory hash mismatch"
        }
        return PotentialBeanFieldManifest(
            root.fieldInt("schemaVersion"),
            root.fieldInt("policyVersion"),
            root.fieldString("variant"),
            root.fieldLong("generation"),
            root.fieldString("configurationSha256"),
            declaredInventorySha256,
            ownedModules.toCollection(linkedSetOf()),
            fields,
            root.fieldInt("retiredLegacyFieldAssignmentCount"),
        )
    }

    fun inventorySha256(fields: Collection<PotentialBeanField>): String =
        Sha256.hex(canonicalFieldRecords(fields).toByteArray(Charsets.UTF_8))

    private fun canonicalFieldRecords(fields: Collection<PotentialBeanField>): String {
        val ordered = fields.sortedWith(POTENTIAL_BEAN_FIELD_ORDER)
        require(ordered.map(PotentialBeanField::key).distinct().size == ordered.size) {
            "potential Bean field records contain duplicate symbol keys"
        }
        ordered.forEach(::validatePotentialBeanField)
        return buildString {
            append('[')
            ordered.forEachIndexed { index, field ->
                if (index > 0) append(',')
                append("{\"modulePath\":").append(fieldJsonString(field.modulePath))
                append(",\"owner\":").append(fieldJsonString(field.key.owner))
                append(",\"name\":").append(fieldJsonString(field.key.name))
                append(",\"descriptor\":").append(fieldJsonString(field.key.descriptor))
                append(",\"access\":").append(field.access).append('}')
            }
            append(']')
        }
    }

    private fun decodeField(value: Any?, label: String): PotentialBeanField {
        val item = value.fieldManifestMap(label)
        item.fieldExactKeys(FIELD_KEYS, label)
        return PotentialBeanField(
            item.fieldString("modulePath"),
            CodeSymbolKey(
                CodeSymbolKind.FIELD,
                item.fieldString("owner"),
                item.fieldString("name"),
                item.fieldString("descriptor"),
            ),
            item.fieldInt("access"),
        ).also(::validatePotentialBeanField)
    }

    private companion object {
        const val MAX_JSON_BYTES = 16 * 1024 * 1024
        val ROOT_KEYS = setOf(
            "schemaVersion",
            "policyVersion",
            "variant",
            "generation",
            "configurationSha256",
            "inventorySha256",
            "ownedModules",
            "fields",
            "retiredLegacyFieldAssignmentCount",
        )
        val FIELD_KEYS = setOf("modulePath", "owner", "name", "descriptor", "access")
    }
}

internal fun validatePotentialBeanField(field: PotentialBeanField) {
    require(field.modulePath.isNotBlank() && field.modulePath.startsWith(':')) {
        "potential Bean field has an invalid module path: ${field.modulePath}"
    }
    validateCodeSymbolKey(field.key)
    require(field.key.kind == CodeSymbolKind.FIELD) { "potential Bean contract must identify a field" }
    require(field.access and DISALLOWED_POTENTIAL_BEAN_FIELD_ACCESS == 0) {
        "potential Bean field has a disallowed static, transient, or synthetic flag: ${field.key.canonicalIdentity}"
    }
}

private fun fieldJsonString(value: String): String = buildString {
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

private fun Any?.fieldManifestMap(label: String): Map<*, *> = this as? Map<*, *>
    ?: throw IllegalArgumentException("$label must be an object")

private fun Map<*, *>.fieldString(key: String): String = this[key] as? String
    ?: throw IllegalArgumentException("$key must be a string")

private fun Map<*, *>.fieldLong(key: String): Long = (this[key] as? Number)?.toLong()
    ?: throw IllegalArgumentException("$key must be a number")

private fun Map<*, *>.fieldInt(key: String): Int {
    val value = fieldLong(key)
    require(value in Int.MIN_VALUE..Int.MAX_VALUE) { "$key must fit a signed 32-bit integer" }
    return value.toInt()
}

private fun Map<*, *>.fieldList(key: String): List<*> = this[key] as? List<*>
    ?: throw IllegalArgumentException("$key must be an array")

private fun Map<*, *>.fieldStringList(key: String): List<String> = fieldList(key).map { value ->
    value as? String ?: throw IllegalArgumentException("$key values must be strings")
}

private fun Map<*, *>.fieldExactKeys(expected: Set<String>, label: String) {
    require(keys == expected) { "$label keys must be exactly $expected" }
}

private val POTENTIAL_BEAN_FIELD_ORDER = compareBy<PotentialBeanField>(
    PotentialBeanField::modulePath,
    { it.key.canonicalIdentity },
)
private val CONFIGURATION_HASH = Regex("[0-9a-f]{64}")
private const val DISALLOWED_POTENTIAL_BEAN_FIELD_ACCESS =
    Opcodes.ACC_STATIC or Opcodes.ACC_TRANSIENT or Opcodes.ACC_SYNTHETIC
