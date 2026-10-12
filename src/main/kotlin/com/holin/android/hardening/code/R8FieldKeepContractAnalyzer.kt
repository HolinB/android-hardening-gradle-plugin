package com.holin.android.hardening.code

import org.objectweb.asm.Opcodes

internal class R8FieldKeepContractAnalyzer {
    fun exclusions(bytecode: BytecodeInventory, effectiveRules: String): List<CodeExclusion> =
        parseContracts(effectiveRules).flatMap { contract ->
            bytecode.ownedClasses.values.asSequence()
                .filter(contract::matchesOwner)
                .flatMap { owner ->
                    owner.fields.asSequence()
                        .filter(contract::matchesField)
                        .map { field ->
                            CodeExclusion(
                                fieldKey(field),
                                CodeExclusionReason.R8_FIELD_KEEP_RULE,
                                "R8 field keep-rule contract ${contract.header} { ${contract.memberClause}; }",
                            )
                        }
                }
                .toList()
        }

    private fun parseContracts(effectiveRules: String): List<FieldKeepContract> =
        CLASS_BLOCK.findAll(stripComments(effectiveRules)).flatMap { match ->
            val directive = match.groupValues[1]
            if (directive.split(',').drop(1).any { modifier -> modifier == "allowobfuscation" }) {
                return@flatMap emptySequence()
            }
            val classAccess = accessTokens(match.groupValues[2], CLASS_ACCESS_TOKENS)
                ?: return@flatMap emptySequence()
            val classPatterns = match.groupValues[4].split(',').map(String::trim)
            if (classPatterns.isEmpty() || classPatterns.any { pattern -> !CLASS_PATTERN.matches(pattern) }) {
                return@flatMap emptySequence()
            }
            val header = match.value.substringBefore('{').trim().replace(WHITESPACE, " ")
            match.groupValues[5].split(';').asSequence().map(String::trim)
                .filter(String::isNotEmpty)
                .mapNotNull { memberClause ->
                    if (!memberClause.endsWith("<fields>")) return@mapNotNull null
                    val fieldAccess = accessTokens(
                        memberClause.removeSuffix("<fields>").trim(),
                        FIELD_ACCESS_TOKENS,
                    ) ?: return@mapNotNull null
                    FieldKeepContract(
                        header,
                        classAccess,
                        match.groupValues[3],
                        classPatterns,
                        memberClause,
                        fieldAccess,
                    )
                }
        }.toList()

    private fun stripComments(rules: String): String = rules.lineSequence().joinToString("\n") { line ->
        line.substringBefore('#')
    }

    private fun accessTokens(value: String, supported: Set<String>): Set<String>? {
        val tokens = value.trim().split(WHITESPACE).filter(String::isNotEmpty)
        return tokens.takeIf { candidates -> candidates.all(supported::contains) }?.toSet()
    }

    private data class FieldKeepContract(
        val header: String,
        val classAccess: Set<String>,
        val classKind: String,
        val classPatterns: List<String>,
        val memberClause: String,
        val fieldAccess: Set<String>,
    ) {
        fun matchesOwner(owner: BytecodeClass): Boolean =
            matchesAccess(owner.access, classAccess) && matchesKind(owner.access) &&
                classPatterns.any { pattern -> matchesClassPattern(pattern, owner.internalName) }

        fun matchesField(field: BytecodeField): Boolean = matchesAccess(field.access, fieldAccess)

        private fun matchesKind(access: Int): Boolean = when (classKind) {
            "class" -> true
            "interface" -> access and Opcodes.ACC_INTERFACE != 0
            "enum" -> access and Opcodes.ACC_ENUM != 0
            else -> false
        }
    }

    private companion object {
        val WHITESPACE = Regex("\\s+")
        val CLASS_BLOCK = Regex(
            """(?ms)^\s*(-keep(?:names|classmembers|classmembernames|classeswithmembers|classeswithmembernames)?(?:,[a-z]+)*)\s+""" +
                """((?:(?:!?[a-z]+)\s+)*)""" +
                """(class|interface|enum)\s+([^\s{]+(?:\s*,\s*[^\s{]+)*)\s*\{([^}]*)}""",
        )
        val CLASS_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_.$*?]*(?:\\.[A-Za-z0-9_.$*?]+)*|\\*\\*?")
        val CLASS_ACCESS_TOKENS = accessTokenSet("public", "private", "protected", "final", "abstract", "synthetic")
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
                else -> return@all false
            }
            val present = access and flag != 0
            if (negated) !present else present
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
    }
}
