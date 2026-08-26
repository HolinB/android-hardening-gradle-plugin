package com.holin.android.hardening.verification

import com.holin.android.hardening.code.JvmClassName
import java.io.BufferedReader
import java.io.StringReader
import java.nio.file.Files
import java.nio.file.Path

enum class SymbolKind {
    CLASS,
    FIELD,
    METHOD,
}

data class MappingSymbolKey(
    val kind: SymbolKind,
    val originalOwner: String,
    val originalName: String,
    val jvmDescriptor: String,
)

data class RetraceCandidate(
    val originalClass: String,
    val originalMethod: String,
    val originalLine: Int,
    val obfuscatedClass: String,
    val obfuscatedMethod: String,
    val obfuscatedLine: Int,
) {
    val obfuscatedFrame: String = "at $obfuscatedClass.$obfuscatedMethod(HardeningSource:$obfuscatedLine)"
}

data class ParsedR8Mapping(
    val compiler: String?,
    val compilerVersion: String?,
    val symbols: Map<MappingSymbolKey, Set<String>>,
    val retraceCandidates: List<RetraceCandidate>,
)

class R8MappingParser {
    fun parse(path: Path, ownedOriginalDescriptors: Set<String>?): ParsedR8Mapping =
        Files.newBufferedReader(path).use { reader -> parse(reader, ownedOriginalDescriptors) }

    fun parse(text: String, ownedOriginalDescriptors: Set<String>?): ParsedR8Mapping =
        BufferedReader(StringReader(text)).use { reader -> parse(reader, ownedOriginalDescriptors) }

    private fun parse(reader: BufferedReader, ownedOriginalDescriptors: Set<String>?): ParsedR8Mapping {
        val ownedRoots = ownedOriginalDescriptors?.mapTo(linkedSetOf()) { descriptor ->
            descriptorToClassName(descriptor)
        }
        val symbols = linkedMapOf<MappingSymbolKey, MutableSet<String>>()
        val candidates = mutableListOf<RetraceCandidate>()
        val methodLines = mutableListOf<MethodMappingLine>()
        var compiler: String? = null
        var compilerVersion: String? = null
        var currentClass: ClassMapping? = null
        var lastMethodLine: MethodMappingLine? = null
        var lineNumber = 0
        reader.forEachLine { line ->
            lineNumber++
            COMPILER.matchEntire(line)?.let { compiler = it.groupValues[1] }
            COMPILER_VERSION.matchEntire(line)?.let { compilerVersion = it.groupValues[1] }
            val trimmed = line.trim()
            if (trimmed.startsWith('#')) {
                if (R8_SYNTHESIZED_METADATA.matches(trimmed)) lastMethodLine?.synthesized = true
                return@forEachLine
            }
            val classMatch = CLASS_MAPPING.matchEntire(line)
            if (classMatch != null) {
                lastMethodLine = null
                val original = classMatch.groupValues[1]
                val obfuscated = classMatch.groupValues[2]
                require(JvmClassName.isDotted(original)) { "invalid R8 mapping class at line $lineNumber" }
                currentClass = if (
                    !obfuscated.startsWith(REMOVED_CLASS_PREFIX) &&
                    (ownedRoots == null || ownedRoots.any { root -> owns(root, original) })
                ) {
                    ClassMapping(original, obfuscated).also {
                        symbols.add(
                            MappingSymbolKey(
                                kind = SymbolKind.CLASS,
                                originalOwner = original,
                                originalName = original,
                                jvmDescriptor = classNameToDescriptor(original),
                            ),
                            obfuscated,
                        )
                    }
                } else {
                    null
                }
                return@forEachLine
            }
            val owner = currentClass ?: return@forEachLine
            if (trimmed.isEmpty()) {
                lastMethodLine = null
                return@forEachLine
            }
            if (!line.first().isWhitespace() || MAPPING_DELIMITER !in trimmed) {
                throw IllegalArgumentException("unsupported R8 mapping content at line $lineNumber")
            }
            val outputName = trimmed.substringAfterLast(MAPPING_DELIMITER)
            require(outputName.isNotBlank() && outputName.none(Char::isWhitespace)) {
                "invalid R8 member mapping output at line $lineNumber"
            }
            val left = trimmed.substringBeforeLast(MAPPING_DELIMITER)
            val lineRange = OBFUSCATED_LINE_RANGE.matchEntire(left)
            val member = lineRange?.groupValues?.get(3) ?: left
            if ('(' in member) {
                val parsed = parseMethod(owner, member, outputName, lineRange, lineNumber)
                parsed.candidate?.let(candidates::add)
                lastMethodLine = MethodMappingLine(
                    holder = owner.original,
                    outputName = outputName,
                    obfuscatedStart = lineRange?.groupValues?.get(1)?.toInt(),
                    obfuscatedEnd = lineRange?.groupValues?.get(2)?.toInt(),
                    parsed = parsed,
                ).also(methodLines::add)
            } else {
                lastMethodLine = null
                parseField(owner, member, lineNumber)?.let { parsed ->
                    symbols.add(parsed, outputName)
                }
            }
        }
        addResidualMethodSymbols(methodLines, symbols)
        return ParsedR8Mapping(
            compiler = compiler,
            compilerVersion = compilerVersion,
            symbols = symbols.mapValues { (_, outputs) -> outputs.toSortedSet() },
            retraceCandidates = candidates.distinct().sortedWith(RETRACE_CANDIDATE_ORDER),
        )
    }

    private fun parseMethod(
        current: ClassMapping,
        member: String,
        outputName: String,
        outputRange: MatchResult?,
        lineNumber: Int,
    ): ParsedMethod {
        val match = METHOD.matchEntire(member)
            ?: throw IllegalArgumentException("invalid R8 method mapping at line $lineNumber")
        val returnType = match.groupValues[1]
        val qualifiedName = match.groupValues[2]
        val (owner, name) = ownerAndName(qualifiedName, current.original)
        val parameters = match.groupValues[3]
            .takeIf(String::isNotBlank)
            ?.split(',')
            ?.map(::typeToDescriptor)
            .orEmpty()
        val descriptor = "(${parameters.joinToString("")})${typeToDescriptor(returnType)}"
        val key = if (owner == current.original && name !in SPECIAL_METHODS) {
            MappingSymbolKey(SymbolKind.METHOD, owner, name, descriptor)
        } else {
            null
        }
        val obfuscatedStart = outputRange?.groupValues?.get(1)?.toInt()
        val originalStart = match.groupValues[4].takeIf(String::isNotEmpty)?.toInt()
        val candidate = if (
            key != null &&
            obfuscatedStart != null && obfuscatedStart > 0 &&
            originalStart != null && originalStart > 0
        ) {
            RetraceCandidate(
                originalClass = owner,
                originalMethod = name,
                originalLine = originalStart,
                obfuscatedClass = current.obfuscated,
                obfuscatedMethod = outputName,
                obfuscatedLine = obfuscatedStart,
            )
        } else {
            null
        }
        return ParsedMethod(key, candidate)
    }

    private fun addResidualMethodSymbols(
        lines: List<MethodMappingLine>,
        symbols: MutableMap<MappingSymbolKey, MutableSet<String>>,
    ) {
        var pendingGroup: MethodRangeGroup? = null
        var pendingLine: MethodMappingLine? = null

        fun flush() {
            val line = pendingLine
            if (line != null && !line.synthesized) {
                line.parsed.key?.let { key -> symbols.add(key, line.outputName) }
            }
            pendingGroup = null
            pendingLine = null
        }

        lines.forEach { line ->
            val start = line.obfuscatedStart
            val end = line.obfuscatedEnd
            if (start == null || end == null) {
                flush()
                if (!line.synthesized) line.parsed.key?.let { key -> symbols.add(key, line.outputName) }
                return@forEach
            }
            val group = MethodRangeGroup(line.holder, line.outputName, start, end)
            if (group != pendingGroup) flush()
            pendingGroup = group
            pendingLine = line
        }
        flush()
    }

    private fun parseField(
        current: ClassMapping,
        member: String,
        lineNumber: Int,
    ): MappingSymbolKey? {
        val match = FIELD.matchEntire(member)
            ?: throw IllegalArgumentException("invalid R8 field mapping at line $lineNumber")
        val (owner, name) = ownerAndName(match.groupValues[2], current.original)
        if (owner != current.original) return null
        return MappingSymbolKey(SymbolKind.FIELD, owner, name, typeToDescriptor(match.groupValues[1]))
    }

    private fun ownerAndName(qualifiedName: String, defaultOwner: String): Pair<String, String> {
        val separator = qualifiedName.lastIndexOf('.')
        return if (separator < 0) {
            defaultOwner to qualifiedName
        } else {
            qualifiedName.substring(0, separator) to qualifiedName.substring(separator + 1)
        }
    }

    private fun typeToDescriptor(javaType: String): String {
        var component = javaType
        var dimensions = 0
        while (component.endsWith("[]")) {
            dimensions++
            component = component.dropLast(2)
        }
        if (component.endsWith("...")) {
            dimensions++
            component = component.dropLast(3)
        }
        val base = PRIMITIVE_DESCRIPTORS[component] ?: run {
            require(JvmClassName.isDotted(component)) { "unsupported R8 mapping type: $javaType" }
            classNameToDescriptor(component)
        }
        return "[".repeat(dimensions) + base
    }

    private fun descriptorToClassName(descriptor: String): String {
        require(descriptor.length >= 3 && descriptor.startsWith('L') && descriptor.endsWith(';')) {
            "owned source descriptor is invalid: $descriptor"
        }
        val internalName = descriptor.substring(1, descriptor.lastIndex)
        require(JvmClassName.isInternal(internalName)) { "owned source descriptor is invalid: $descriptor" }
        return internalName.replace('/', '.')
    }

    private fun classNameToDescriptor(className: String): String {
        require(JvmClassName.isDotted(className)) { "unsupported R8 mapping type: $className" }
        return "L${className.replace('.', '/')};"
    }

    private fun owns(root: String, candidate: String): Boolean = candidate == root || candidate.startsWith("$root${'$'}")

    private fun MutableMap<MappingSymbolKey, MutableSet<String>>.add(key: MappingSymbolKey, output: String) {
        getOrPut(key, ::linkedSetOf).add(output)
    }

    private data class ClassMapping(val original: String, val obfuscated: String)
    private data class ParsedMethod(val key: MappingSymbolKey?, val candidate: RetraceCandidate?)
    private data class MethodRangeGroup(
        val holder: String,
        val outputName: String,
        val obfuscatedStart: Int,
        val obfuscatedEnd: Int,
    )
    private data class MethodMappingLine(
        val holder: String,
        val outputName: String,
        val obfuscatedStart: Int?,
        val obfuscatedEnd: Int?,
        val parsed: ParsedMethod,
        var synthesized: Boolean = false,
    )

    private companion object {
        const val MAPPING_DELIMITER = " -> "
        const val REMOVED_CLASS_PREFIX = "R8${'$'}${'$'}REMOVED${'$'}${'$'}CLASS${'$'}${'$'}"
        val COMPILER = Regex("^# compiler: (\\S+)$")
        val COMPILER_VERSION = Regex("^# compiler_version: (\\S+)$")
        val CLASS_MAPPING = Regex("^([^#\\s].*?) -> ([^\\s]+):$")
        val OBFUSCATED_LINE_RANGE = Regex("^(\\d+):(\\d+):(.*)$")
        val METHOD = Regex("^([^\\s]+)\\s+([^\\s(]+)\\(([^)]*)\\)(?::(\\d+)(?::(\\d+))?)?$")
        val FIELD = Regex("^([^\\s]+)\\s+([^\\s]+)$")
        val R8_SYNTHESIZED_METADATA = Regex(
            "^#\\s*\\{\\s*\"id\"\\s*:\\s*\"com\\.android\\.tools\\.r8\\.synthesized\"\\s*}$",
        )
        val SPECIAL_METHODS = setOf("<init>", "<clinit>")
        val PRIMITIVE_DESCRIPTORS = mapOf(
            "void" to "V",
            "boolean" to "Z",
            "byte" to "B",
            "char" to "C",
            "short" to "S",
            "int" to "I",
            "long" to "J",
            "float" to "F",
            "double" to "D",
        )
        val RETRACE_CANDIDATE_ORDER = compareBy<RetraceCandidate>(
            RetraceCandidate::originalClass,
            RetraceCandidate::originalMethod,
            RetraceCandidate::originalLine,
            RetraceCandidate::obfuscatedClass,
            RetraceCandidate::obfuscatedMethod,
        )
    }
}

data class MappingContinuityMismatch(
    val key: MappingSymbolKey,
    val previousObfuscatedNames: List<String>,
    val currentObfuscatedNames: List<String>,
)

data class MappingContinuityResult(
    val previousCount: Int,
    val applicableCount: Int,
    val stableCount: Int,
    val noLongerPresentCount: Int,
    val mismatches: List<MappingContinuityMismatch>,
)

class MappingContinuityVerifier {
    fun verify(previous: ParsedR8Mapping, current: ParsedR8Mapping): MappingContinuityResult {
        var applicable = 0
        var stable = 0
        val mismatches = mutableListOf<MappingContinuityMismatch>()
        previous.symbols.keys.sortedWith(SYMBOL_ORDER).forEach { key ->
            val currentNames = current.symbols[key] ?: return@forEach
            applicable++
            val previousNames = previous.symbols.getValue(key)
            if (previousNames == currentNames) {
                stable++
            } else {
                mismatches += MappingContinuityMismatch(
                    key = key,
                    previousObfuscatedNames = previousNames.sorted(),
                    currentObfuscatedNames = currentNames.sorted(),
                )
            }
        }
        return MappingContinuityResult(
            previousCount = previous.symbols.size,
            applicableCount = applicable,
            stableCount = stable,
            noLongerPresentCount = previous.symbols.size - applicable,
            mismatches = mismatches,
        )
    }

    companion object {
        val SYMBOL_ORDER: Comparator<MappingSymbolKey> = compareBy<MappingSymbolKey>(
            { it.kind.ordinal },
            MappingSymbolKey::originalOwner,
            MappingSymbolKey::originalName,
            MappingSymbolKey::jvmDescriptor,
        )
    }
}
