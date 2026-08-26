package com.holin.android.hardening.code

import com.holin.android.hardening.state.StrictJson
import groovy.json.JsonSlurper
import java.util.ArrayList
import java.util.Collections
import java.util.LinkedHashSet
import java.util.Locale

class CodeNamingManifest(
    val schemaVersion: Int,
    val variant: String,
    val generation: Long,
    ownedModules: Set<String>,
    val mappingSha256: String,
    val registrySha256: String,
    expectedSymbols: Collection<AssignedCodeName>,
    exclusions: Collection<CodeExclusion>,
) {
    val ownedModules: Set<String> = Collections.unmodifiableSet(LinkedHashSet(ownedModules.sorted()))
    val expectedSymbols: List<AssignedCodeName> = Collections.unmodifiableList(
        ArrayList(expectedSymbols.sortedWith(ASSIGNMENT_ORDER)),
    )
    val exclusions: List<CodeExclusion> = Collections.unmodifiableList(
        ArrayList(exclusions.sortedWith(MANIFEST_EXCLUSION_ORDER)),
    )

    init {
        require(schemaVersion == 1) { "unsupported code naming manifest schema $schemaVersion" }
        require(variant.isNotBlank()) { "code naming manifest variant must not be blank" }
        require(generation > 0) { "code naming manifest generation must be positive" }
        require(this.ownedModules.isNotEmpty()) { "code naming manifest owned modules must not be empty" }
        requireSha256(mappingSha256, "mappingSha256")
        requireSha256(registrySha256, "registrySha256")
        require(this.expectedSymbols.map(AssignedCodeName::key).distinct().size == this.expectedSymbols.size) {
            "code naming manifest contains duplicate expected symbols"
        }
        require(this.exclusions.distinct().size == this.exclusions.size) {
            "code naming manifest contains duplicate exclusions"
        }
        require(this.expectedSymbols.none { assignment -> assignment.key in this.exclusions.map(CodeExclusion::key) }) {
            "code naming manifest symbol cannot be both expected and excluded"
        }
        this.expectedSymbols.forEach(::validateAssignedCodeName)
        this.exclusions.forEach { validateCodeSymbolKey(it.key) }
        validateNamingProvenance(this.expectedSymbols, this.exclusions)
    }

    override fun equals(other: Any?): Boolean = other is CodeNamingManifest &&
        schemaVersion == other.schemaVersion && variant == other.variant && generation == other.generation &&
        ownedModules == other.ownedModules && mappingSha256 == other.mappingSha256 &&
        registrySha256 == other.registrySha256 && expectedSymbols == other.expectedSymbols && exclusions == other.exclusions

    override fun hashCode(): Int = listOf(
        schemaVersion,
        variant,
        generation,
        ownedModules,
        mappingSha256,
        registrySha256,
        expectedSymbols,
        exclusions,
    ).hashCode()

    override fun toString(): String = "CodeNamingManifest(schemaVersion=$schemaVersion, variant=$variant, " +
        "generation=$generation, ownedModules=$ownedModules, mappingSha256=$mappingSha256, " +
        "registrySha256=$registrySha256, expectedSymbols=$expectedSymbols, exclusions=$exclusions)"
}

class CodeNamingManifestCodec {
    fun encode(manifest: CodeNamingManifest): String = buildString {
        append("{\"schemaVersion\":").append(manifest.schemaVersion)
        append(",\"variant\":").append(jsonString(manifest.variant))
        append(",\"generation\":").append(manifest.generation)
        append(",\"ownedModules\":[")
        manifest.ownedModules.forEachIndexed { index, module ->
            if (index > 0) append(',')
            append(jsonString(module))
        }
        append("],\"mappingSha256\":").append(jsonString(manifest.mappingSha256))
        append(",\"registrySha256\":").append(jsonString(manifest.registrySha256))
        append(",\"expectedSymbols\":[")
        manifest.expectedSymbols.forEachIndexed { index, assignment ->
            if (index > 0) append(',')
            append("{\"kind\":").append(jsonString(assignment.key.kind.name))
            append(",\"owner\":").append(jsonString(assignment.key.owner))
            append(",\"name\":").append(jsonString(assignment.key.name))
            append(",\"descriptor\":").append(jsonString(assignment.key.descriptor))
            append(",\"alias\":").append(jsonString(assignment.alias))
            append(",\"outputOwner\":").append(jsonString(assignment.outputOwner)).append('}')
        }
        append("],\"exclusions\":[")
        manifest.exclusions.forEachIndexed { index, exclusion ->
            if (index > 0) append(',')
            append("{\"kind\":").append(jsonString(exclusion.key.kind.name))
            append(",\"owner\":").append(jsonString(exclusion.key.owner))
            append(",\"name\":").append(jsonString(exclusion.key.name))
            append(",\"descriptor\":").append(jsonString(exclusion.key.descriptor))
            append(",\"reason\":").append(jsonString(exclusion.reason.name))
            append(",\"evidence\":").append(jsonString(exclusion.evidence)).append('}')
        }
        append("]}\n")
    }

    fun decode(json: String): CodeNamingManifest {
        require(json.toByteArray(Charsets.UTF_8).size <= MAX_JSON_BYTES) {
            "code naming manifest exceeds the 16 MiB input limit"
        }
        StrictJson.validate(json)
        val root = JsonSlurper().parseText(json).manifestMap("manifest")
        root.exactKeys(ROOT_KEYS, "manifest")
        val ownedModules = root.manifestStringList("ownedModules")
        require(ownedModules.distinct().size == ownedModules.size) {
            "code naming manifest contains duplicate owned modules"
        }
        return CodeNamingManifest(
            schemaVersion = root.manifestInt("schemaVersion"),
            variant = root.manifestString("variant"),
            generation = root.manifestLong("generation"),
            ownedModules = ownedModules.toCollection(linkedSetOf()),
            mappingSha256 = root.manifestString("mappingSha256"),
            registrySha256 = root.manifestString("registrySha256"),
            expectedSymbols = root.manifestList("expectedSymbols").mapIndexed { index, value ->
                decodeAssignment(value, "expectedSymbols[$index]")
            },
            exclusions = root.manifestList("exclusions").mapIndexed { index, value ->
                decodeExclusion(value, "exclusions[$index]")
            },
        )
    }

    private fun decodeAssignment(value: Any?, label: String): AssignedCodeName {
        val item = value.manifestMap(label)
        item.exactKeys(ASSIGNMENT_KEYS, label)
        return AssignedCodeName(
            key = decodeKey(item),
            alias = item.manifestString("alias"),
            outputOwner = item.manifestString("outputOwner"),
        )
    }

    private fun decodeExclusion(value: Any?, label: String): CodeExclusion {
        val item = value.manifestMap(label)
        item.exactKeys(EXCLUSION_KEYS, label)
        return CodeExclusion(
            key = decodeKey(item),
            reason = enumValueOf(item.manifestString("reason")),
            evidence = item.manifestString("evidence"),
        )
    }

    private fun decodeKey(item: Map<*, *>): CodeSymbolKey = CodeSymbolKey(
        kind = enumValueOf(item.manifestString("kind")),
        owner = item.manifestString("owner"),
        name = item.manifestString("name"),
        descriptor = item.manifestString("descriptor"),
    )

    private companion object {
        const val MAX_JSON_BYTES = 16 * 1024 * 1024
        val ROOT_KEYS = setOf(
            "schemaVersion", "variant", "generation", "ownedModules", "mappingSha256", "registrySha256",
            "expectedSymbols", "exclusions",
        )
        val KEY_KEYS = setOf("kind", "owner", "name", "descriptor")
        val ASSIGNMENT_KEYS = KEY_KEYS + setOf("alias", "outputOwner")
        val EXCLUSION_KEYS = KEY_KEYS + setOf("reason", "evidence")
    }
}

internal fun validateAssignedCodeName(assignment: AssignedCodeName) {
    validateCodeSymbolKey(assignment.key)
    require(STRICT_OUTPUT_INTERNAL_NAME.matches(assignment.outputOwner)) { "invalid output owner: ${assignment.outputOwner}" }
    val aliasShape = if (assignment.key.kind == CodeSymbolKind.CLASS) CLASS_ALIAS else MEMBER_ALIAS
    require(aliasShape.matches(assignment.alias)) { "invalid ${assignment.key.kind} alias: ${assignment.alias}" }
    if (assignment.key.kind == CodeSymbolKind.CLASS) {
        require(assignment.outputOwner.substringAfterLast('/') == assignment.alias) {
            "class output owner must end with its alias"
        }
    }
    require(assignment.key.kind != CodeSymbolKind.METHOD || assignment.key.name !in SPECIAL_METHOD_NAMES) {
        "constructors and class initializers cannot be expected renamed symbols"
    }
}

private fun validateNamingProvenance(
    expectedSymbols: List<AssignedCodeName>,
    exclusions: List<CodeExclusion>,
) {
    val classAssignments = expectedSymbols
        .filter { assignment -> assignment.key.kind == CodeSymbolKind.CLASS }
        .associateBy { assignment -> assignment.key.owner }
    val preservedClassOwners = exclusions
        .filter { exclusion -> exclusion.key.kind == CodeSymbolKind.CLASS }
        .mapTo(hashSetOf()) { exclusion -> exclusion.key.owner }
    expectedSymbols.filter { assignment -> assignment.key.kind != CodeSymbolKind.CLASS }.forEach { assignment ->
        require(assignment.key.owner in classAssignments || assignment.key.owner in preservedClassOwners) {
            "expected member owner has no mapped or preserved class: ${assignment.key.owner}"
        }
    }
    expectedSymbols.groupBy { assignment -> assignment.key.owner }.forEach { (owner, assignments) ->
        val outputOwners = assignments.mapTo(linkedSetOf(), AssignedCodeName::outputOwner)
        require(outputOwners.size == 1) { "expected symbols disagree on output owner for $owner" }
        val expectedOutputOwner = classAssignments[owner]?.outputOwner ?: owner
        require(outputOwners.single() == expectedOutputOwner) {
            "expected symbol output owner does not match the class mapping for $owner"
        }
    }

    val effectiveClassOutputs = classAssignments.values.map(AssignedCodeName::outputOwner) + preservedClassOwners
    require(effectiveClassOutputs.distinctBy { output -> output.lowercase(Locale.ROOT) }.size == effectiveClassOutputs.size) {
        "mapped and preserved class outputs collide case-insensitively"
    }

    expectedSymbols.filter { assignment -> assignment.key.kind != CodeSymbolKind.CLASS }
        .groupBy { assignment -> assignment.alias.lowercase(Locale.ROOT) }
        .values
        .filter { assignments -> assignments.size > 1 }
        .forEach { assignments ->
            require(
                assignments.all { assignment -> assignment.key.kind == CodeSymbolKind.METHOD } &&
                    assignments.map { assignment -> assignment.key.name }.distinct().size == 1,
            ) { "member aliases collide outside one method family" }
        }
}

internal fun validateCodeSymbolKey(key: CodeSymbolKey) {
    require(JvmClassName.isInternal(key.owner)) { "invalid code symbol owner: ${key.owner}" }
    when (key.kind) {
        CodeSymbolKind.CLASS -> {
            require(key.name == key.owner.substringAfterLast('/')) { "class name does not match owner" }
            require(key.descriptor == "L${key.owner};") { "class descriptor does not match owner" }
        }
        CodeSymbolKind.FIELD -> {
            requireValidMemberName(key.name, allowSpecial = false)
            ExactJvmDescriptor.fieldType(key.descriptor)
        }
        CodeSymbolKind.METHOD -> {
            requireValidMemberName(key.name, allowSpecial = true)
            ExactJvmDescriptor.methodType(key.descriptor)
        }
    }
}

private fun requireValidMemberName(name: String, allowSpecial: Boolean) {
    if (allowSpecial && name in SPECIAL_METHOD_NAMES) return
    require(name.isNotEmpty()) { "code member name must not be empty" }
    require(name.none { it.isWhitespace() || it.isISOControl() || it in FORBIDDEN_MEMBER_NAME_CHARACTERS }) {
        "invalid code member name: $name"
    }
    require(!allowSpecial || '<' !in name && '>' !in name) { "invalid code method name: $name" }
}

internal data class ExactJvmMethodType(val parameterTypes: List<String>, val returnType: String)

internal object ExactJvmDescriptor {
    fun fieldType(descriptor: String): String {
        val parsed = parseType(descriptor, 0, allowVoid = false)
        require(parsed.nextIndex == descriptor.length) { "trailing JVM field descriptor content: $descriptor" }
        return parsed.javaType
    }

    fun methodType(descriptor: String): ExactJvmMethodType {
        require(descriptor.startsWith('(')) { "invalid JVM method descriptor: $descriptor" }
        val parameters = mutableListOf<String>()
        var index = 1
        while (descriptor.getOrNull(index) != ')') {
            require(index < descriptor.length) { "unterminated JVM method descriptor: $descriptor" }
            val parameter = parseType(descriptor, index, allowVoid = false)
            parameters += parameter.javaType
            index = parameter.nextIndex
        }
        val returnType = parseType(descriptor, index + 1, allowVoid = true)
        require(returnType.nextIndex == descriptor.length) { "trailing JVM method descriptor content: $descriptor" }
        return ExactJvmMethodType(parameters, returnType.javaType)
    }

    fun referencedInternalNamesInField(descriptor: String): Set<String> {
        fieldType(descriptor)
        return referencedInternalNames(descriptor)
    }

    fun referencedInternalNamesInMethod(descriptor: String): Set<String> {
        methodType(descriptor)
        return referencedInternalNames(descriptor)
    }

    private fun referencedInternalNames(descriptor: String): Set<String> {
        val names = linkedSetOf<String>()
        var index = 0
        while (index < descriptor.length) {
            if (descriptor[index] != 'L') {
                index++
                continue
            }
            val end = descriptor.indexOf(';', startIndex = index + 1)
            check(end > index + 1)
            names += descriptor.substring(index + 1, end)
            index = end + 1
        }
        return names
    }

    private fun parseType(descriptor: String, startIndex: Int, allowVoid: Boolean): ParsedJvmType {
        require(startIndex < descriptor.length) { "missing JVM descriptor type: $descriptor" }
        var index = startIndex
        var dimensions = 0
        while (descriptor.getOrNull(index) == '[') {
            dimensions++
            index++
        }
        require(index < descriptor.length) { "incomplete JVM array descriptor: $descriptor" }
        val marker = descriptor[index]
        val (baseType, nextIndex) = when (marker) {
            'V' -> {
                require(allowVoid && dimensions == 0) { "void is not valid in this JVM descriptor: $descriptor" }
                "void" to index + 1
            }
            'Z' -> "boolean" to index + 1
            'B' -> "byte" to index + 1
            'C' -> "char" to index + 1
            'S' -> "short" to index + 1
            'I' -> "int" to index + 1
            'J' -> "long" to index + 1
            'F' -> "float" to index + 1
            'D' -> "double" to index + 1
            'L' -> {
                val end = descriptor.indexOf(';', startIndex = index + 1)
                require(end > index + 1) { "unterminated JVM object descriptor: $descriptor" }
                val internalName = descriptor.substring(index + 1, end)
                require(JvmClassName.isInternal(internalName)) { "invalid JVM object descriptor: $descriptor" }
                internalName.replace('/', '.') to end + 1
            }
            else -> throw IllegalArgumentException("invalid JVM descriptor type '$marker': $descriptor")
        }
        return ParsedJvmType(baseType + "[]".repeat(dimensions), nextIndex)
    }

    private data class ParsedJvmType(val javaType: String, val nextIndex: Int)
}

private fun requireSha256(value: String, label: String) {
    require(SHA256.matches(value)) { "$label must be a lowercase SHA-256" }
}

private fun jsonString(value: String): String = buildString {
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

private fun Any?.manifestMap(label: String): Map<*, *> = this as? Map<*, *> ?: invalidManifest("$label must be an object")
private fun Map<*, *>.manifestString(key: String): String = this[key] as? String ?: invalidManifest("$key must be a string")
private fun Map<*, *>.manifestLong(key: String): Long = (this[key] as? Number)?.toLong()
    ?: invalidManifest("$key must be a number")
private fun Map<*, *>.manifestInt(key: String): Int {
    val value = manifestLong(key)
    require(value in Int.MIN_VALUE..Int.MAX_VALUE) { "$key must fit a signed 32-bit integer" }
    return value.toInt()
}
private fun Map<*, *>.manifestList(key: String): List<*> = this[key] as? List<*>
    ?: invalidManifest("$key must be an array")
private fun Map<*, *>.manifestStringList(key: String): List<String> = manifestList(key).map { value ->
    value as? String ?: invalidManifest("$key values must be strings")
}
private fun Map<*, *>.exactKeys(expected: Set<String>, label: String) {
    require(keys == expected) { "$label keys must be exactly $expected" }
}
private fun invalidManifest(message: String): Nothing = throw IllegalArgumentException(message)

private val ASSIGNMENT_ORDER = compareBy<AssignedCodeName>(
    { it.key.canonicalIdentity },
    { it.key.kind.name },
    AssignedCodeName::alias,
    AssignedCodeName::outputOwner,
)
private val MANIFEST_EXCLUSION_ORDER = compareBy<CodeExclusion>(
    { it.key.canonicalIdentity },
    { it.key.kind.name },
    { it.reason.ordinal },
    CodeExclusion::evidence,
)
private val SHA256 = Regex("[0-9a-f]{64}")
private val STRICT_OUTPUT_INTERNAL_NAME = Regex("[A-Za-z_${'$'}][A-Za-z0-9_${'$'}]*(?:/[A-Za-z_${'$'}][A-Za-z0-9_${'$'}]*)*")
private val CLASS_ALIAS = Regex("[A-Z][A-Za-z0-9]*")
private val MEMBER_ALIAS = Regex("[a-z][A-Za-z0-9]*")
private val SPECIAL_METHOD_NAMES = setOf("<init>", "<clinit>")
private val FORBIDDEN_MEMBER_NAME_CHARACTERS = setOf('.', ';', '[', '/', '(')
