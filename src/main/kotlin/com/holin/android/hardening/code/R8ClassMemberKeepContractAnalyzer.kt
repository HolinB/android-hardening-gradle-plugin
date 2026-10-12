package com.holin.android.hardening.code

import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type

/** Excludes names that a supported R8 keep rule provably prevents from being obfuscated. */
internal class R8ClassMemberKeepContractAnalyzer {
    fun exclusions(bytecode: BytecodeInventory, effectiveRules: String): List<CodeExclusion> =
        parseContracts(effectiveRules).flatMap { contract ->
            bytecode.ownedClasses.values.asSequence()
                .filter { owner -> contract.matchesOwner(owner, bytecode) }
                .flatMap { owner -> contract.exclusions(owner, bytecode).asSequence() }
                .toList()
        }.groupBy(CodeExclusion::key)
            .values
            .map { candidates -> candidates.minBy(CodeExclusion::evidence) }
            .sortedWith(compareBy({ it.key.canonicalIdentity }, { it.key.kind.name }))

    private fun parseContracts(effectiveRules: String): List<ClassMemberKeepContract> =
        CLASS_RULE.findAll(stripComments(effectiveRules)).mapNotNull { match ->
            val directive = match.groupValues[1]
            val modifiers = directive.split(',').drop(1)
            if (modifiers.any { modifier -> modifier == "allowobfuscation" || modifier !in SUPPORTED_MODIFIERS }) {
                return@mapNotNull null
            }
            val classAccess = accessTokens(match.groupValues[2], CLASS_ACCESS_TOKENS)
                ?: return@mapNotNull null
            val classPatterns = match.groupValues[4].split(',').map(String::trim)
            if (classPatterns.isEmpty() || classPatterns.any { pattern -> !CLASS_PATTERN.matches(pattern) }) {
                return@mapNotNull null
            }
            val relation = match.groupValues[5].ifBlank { null }
            val ancestorPattern = match.groupValues[6].ifBlank { null }
            if (relation != null && (ancestorPattern == null || !CLASS_PATTERN.matches(ancestorPattern))) {
                return@mapNotNull null
            }
            val header = match.value.substringBefore('{').trim().replace(WHITESPACE, " ")
            ClassMemberKeepContract(
                header,
                classAccess,
                match.groupValues[3],
                classPatterns,
                relation,
                ancestorPattern,
                "includedescriptorclasses" in modifiers,
                parseMemberContracts(match.groupValues[7]),
            )
        }.toList()

    private fun parseMemberContracts(block: String): List<MemberKeepContract> =
        block.split(';').asSequence()
            .map(String::trim)
            .filter(String::isNotEmpty)
            .mapNotNull { clause ->
                when {
                    clause == "*" -> MemberKeepContract(clause, MemberKind.ALL, emptySet())
                    clause.endsWith("<fields>") -> accessTokens(
                        clause.removeSuffix("<fields>").trim(),
                        FIELD_ACCESS_TOKENS,
                    )?.let { access -> MemberKeepContract(clause, MemberKind.FIELD, access) }
                    clause.endsWith("<methods>") -> accessTokens(
                        clause.removeSuffix("<methods>").trim(),
                        METHOD_ACCESS_TOKENS,
                    )?.let { access -> MemberKeepContract(clause, MemberKind.METHOD, access) }
                    else -> null
                }
            }.toList()

    private fun stripComments(rules: String): String = rules.lineSequence().joinToString("\n") { line ->
        line.substringBefore('#')
    }

    private fun accessTokens(value: String, supported: Set<String>): Set<String>? {
        val tokens = value.trim().split(WHITESPACE).filter(String::isNotEmpty)
        if (tokens.any { token -> token.startsWith('@') || token !in supported }) return null
        return tokens.toSet()
    }

    private data class ClassMemberKeepContract(
        val header: String,
        val classAccess: Set<String>,
        val classKind: String,
        val classPatterns: List<String>,
        val relation: String?,
        val ancestorPattern: String?,
        val includeDescriptorClasses: Boolean,
        val members: List<MemberKeepContract>,
    ) {
        fun matchesOwner(owner: BytecodeClass, bytecode: BytecodeInventory): Boolean {
            if (!matchesAccess(owner.access, classAccess) || !matchesKind(owner.access)) return false
            if (classPatterns.none { pattern -> matchesClassPattern(pattern, owner.internalName) }) return false
            val ancestor = ancestorPattern ?: return relation == null
            return matchesHierarchy(owner, ancestor, bytecode)
        }

        fun exclusions(owner: BytecodeClass, bytecode: BytecodeInventory): List<CodeExclusion> = buildList {
            val matchingFields = owner.fields.filter { field -> members.any { contract -> contract.matchesField(field) } }
            val matchingMethods = owner.methods.filter { method -> members.any { contract -> contract.matchesMethod(method) } }
            add(exclusion(classKey(owner), "class name"))
            matchingFields.forEach { field -> add(exclusion(fieldKey(field), "field ${field.name}")) }
            matchingMethods.forEach { method -> add(exclusion(methodKey(method), "method ${method.name}${method.descriptor}")) }
            if (includeDescriptorClasses) {
                (matchingFields.map(BytecodeField::descriptor) + matchingMethods.map(BytecodeMethod::descriptor))
                    .asSequence()
                    .flatMap { descriptor -> descriptorClassNames(descriptor).asSequence() }
                    .distinct()
                    .mapNotNull(bytecode.ownedClasses::get)
                    .forEach { descriptorOwner ->
                        add(exclusion(classKey(descriptorOwner), "descriptor class ${descriptorOwner.internalName}"))
                    }
            }
        }

        private fun exclusion(key: CodeSymbolKey, matched: String) = CodeExclusion(
            key,
            CodeExclusionReason.R8_CLASS_MEMBER_KEEP_RULE,
            "R8 class/member keep-rule contract $header: matched $matched",
        )

        private fun matchesKind(access: Int): Boolean = when (classKind) {
            // ProGuard's "class" keyword matches classes and interfaces.
            "class" -> true
            "interface" -> access and Opcodes.ACC_INTERFACE != 0
            "enum" -> access and Opcodes.ACC_ENUM != 0
            else -> false
        }
    }

    private data class MemberKeepContract(
        val clause: String,
        val kind: MemberKind,
        val access: Set<String>,
    ) {
        fun matchesField(field: BytecodeField): Boolean =
            kind in setOf(MemberKind.ALL, MemberKind.FIELD) && matchesAccess(field.access, access)

        fun matchesMethod(method: BytecodeMethod): Boolean =
            kind in setOf(MemberKind.ALL, MemberKind.METHOD) && matchesAccess(method.access, access)
    }

    private enum class MemberKind { ALL, FIELD, METHOD }

    private companion object {
        val WHITESPACE = Regex("\\s+")
        val CLASS_RULE = Regex(
            """(?ms)^\s*(-keep(?:names)?(?:,[a-z]+)*)\s+((?:(?:!?[a-z]+|@\S+)\s+)*)""" +
                """(class|interface|enum)\s+([^\s{]+(?:\s*,\s*[^\s{]+)*)""" +
                """(?:\s+(extends|implements)\s+([^\s,{]+))?\s*(?:\{([^}]*)})?""",
        )
        val CLASS_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_.$*?]*(?:\\.[A-Za-z0-9_.$*?]+)*|\\*\\*?")
        val SUPPORTED_MODIFIERS = setOf(
            "allowoptimization",
            "allowshrinking",
            "includedescriptorclasses",
            "includecode",
        )
        val CLASS_ACCESS_TOKENS = accessTokenSet(
            "public",
            "private",
            "protected",
            "final",
            "abstract",
            "synthetic",
        )
        val FIELD_ACCESS_TOKENS = accessTokenSet(
            "public",
            "private",
            "protected",
            "static",
            "final",
            "transient",
            "volatile",
            "synthetic",
            "enum",
        )
        val METHOD_ACCESS_TOKENS = accessTokenSet(
            "public",
            "private",
            "protected",
            "static",
            "final",
            "synchronized",
            "bridge",
            "varargs",
            "native",
            "abstract",
            "strict",
            "synthetic",
        )

        fun accessTokenSet(vararg tokens: String): Set<String> = buildSet {
            tokens.forEach { token ->
                add(token)
                add("!$token")
            }
        }

        fun matchesAccess(access: Int, tokens: Set<String>): Boolean = tokens.all { token ->
            val negated = token.startsWith('!')
            val flag = when (token.removePrefix("!")) {
                "public" -> Opcodes.ACC_PUBLIC
                "private" -> Opcodes.ACC_PRIVATE
                "protected" -> Opcodes.ACC_PROTECTED
                "static" -> Opcodes.ACC_STATIC
                "final" -> Opcodes.ACC_FINAL
                "transient" -> Opcodes.ACC_TRANSIENT
                "volatile" -> Opcodes.ACC_VOLATILE
                "synthetic" -> Opcodes.ACC_SYNTHETIC
                "enum" -> Opcodes.ACC_ENUM
                "abstract" -> Opcodes.ACC_ABSTRACT
                "synchronized" -> Opcodes.ACC_SYNCHRONIZED
                "bridge" -> Opcodes.ACC_BRIDGE
                "varargs" -> Opcodes.ACC_VARARGS
                "native" -> Opcodes.ACC_NATIVE
                "strict" -> Opcodes.ACC_STRICT
                else -> return@all false
            }
            val present = access and flag != 0
            if (negated) !present else present
        }

        fun matchesHierarchy(owner: BytecodeClass, pattern: String, bytecode: BytecodeInventory): Boolean {
            val pending = ArrayDeque<String>()
            owner.superName?.let(pending::addLast)
            owner.interfaces.forEach(pending::addLast)
            val visited = mutableSetOf<String>()
            while (pending.isNotEmpty()) {
                val name = pending.removeFirst()
                if (!visited.add(name)) continue
                if (matchesClassPattern(pattern, name)) return true
                bytecode.hierarchyClasses[name]?.let { ancestor ->
                    ancestor.superName?.let(pending::addLast)
                    ancestor.interfaces.forEach(pending::addLast)
                }
            }
            return false
        }

        fun matchesClassPattern(pattern: String, internalName: String): Boolean {
            if (pattern == "*" || pattern == "**") return true
            val dottedName = internalName.replace('/', '.')
            val expression = buildString {
                append('^')
                var index = 0
                while (index < pattern.length) {
                    when (val character = pattern[index]) {
                        '*' -> {
                            if (index + 1 < pattern.length && pattern[index + 1] == '*') {
                                append(".*")
                                index++
                            } else {
                                append("[^.]*")
                            }
                        }
                        '?' -> append("[^.]")
                        '.', '$' -> append('\\').append(character)
                        else -> append(character)
                    }
                    index++
                }
                append('$')
            }
            return Regex(expression).matches(dottedName)
        }

        fun descriptorClassNames(descriptor: String): Set<String> {
            val names = linkedSetOf<String>()
            fun collect(type: Type) {
                when (type.sort) {
                    Type.OBJECT -> names += type.internalName
                    Type.ARRAY -> collect(type.elementType)
                    Type.METHOD -> {
                        type.argumentTypes.forEach(::collect)
                        collect(type.returnType)
                    }
                }
            }
            collect(Type.getType(descriptor))
            return names
        }
    }
}
