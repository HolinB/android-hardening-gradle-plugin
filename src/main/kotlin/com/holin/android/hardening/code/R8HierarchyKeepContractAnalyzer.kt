package com.holin.android.hardening.code

import org.objectweb.asm.Opcodes

internal class R8HierarchyKeepContractAnalyzer {
    fun exclusions(bytecode: BytecodeInventory, effectiveRules: String): List<CodeExclusion> =
        parseContracts(effectiveRules).flatMap { contract ->
            bytecode.ownedClasses.values.asSequence()
                .filter(contract::matchesDeclaration)
                .mapNotNull { owner -> contract.matchingAncestor(owner, bytecode)?.let { owner to it } }
                .map { (owner, ancestor) ->
                    CodeExclusion(
                        classKey(owner),
                        CodeExclusionReason.R8_HIERARCHY_KEEP_RULE,
                        "R8 hierarchy keep-rule contract ${contract.header}: matched ancestor $ancestor",
                    )
                }
                .toList()
        }

    private fun parseContracts(effectiveRules: String): List<HierarchyKeepContract> =
        HIERARCHY_RULE.findAll(stripComments(effectiveRules)).mapNotNull { match ->
            val directive = match.groupValues[1]
            if (directive.split(',').drop(1).any { modifier -> modifier == "allowobfuscation" }) {
                return@mapNotNull null
            }
            val accessTokens = match.groupValues[2].trim().split(WHITESPACE).filter(String::isNotEmpty)
            if (accessTokens.any { token -> token.startsWith('@') || token !in SUPPORTED_ACCESS_TOKENS }) {
                return@mapNotNull null
            }
            val classPattern = match.groupValues[4]
            val ancestorPattern = match.groupValues[6]
            if (!isSupportedClassPattern(classPattern) || !isSupportedClassPattern(ancestorPattern)) {
                return@mapNotNull null
            }
            HierarchyKeepContract(
                match.value.trim().replace(WHITESPACE, " "),
                accessTokens.toSet(),
                match.groupValues[3],
                classPattern,
                match.groupValues[5],
                ancestorPattern,
            )
        }.toList()

    private fun stripComments(rules: String): String = rules.lineSequence().joinToString("\n") { line ->
        line.substringBefore('#')
    }

    private fun isSupportedClassPattern(pattern: String): Boolean = CLASS_PATTERN.matches(pattern)

    private data class HierarchyKeepContract(
        val header: String,
        val accessTokens: Set<String>,
        val classKind: String,
        val classPattern: String,
        val relation: String,
        val ancestorPattern: String,
    ) {
        fun matchesDeclaration(owner: BytecodeClass): Boolean {
            if (!matchesAccess(owner.access)) return false
            if (!matchesKind(owner.access)) return false
            return matchesClassPattern(classPattern, owner.internalName)
        }

        fun matchingAncestor(owner: BytecodeClass, bytecode: BytecodeInventory): String? = when (relation) {
            "extends", "implements" ->
                matchingSuperclass(owner, bytecode) ?: matchingInterface(owner, bytecode)
            else -> null
        }

        private fun matchesAccess(access: Int): Boolean = accessTokens.all { token ->
            val negated = token.startsWith('!')
            val flag = when (token.removePrefix("!")) {
                "public" -> Opcodes.ACC_PUBLIC
                "private" -> Opcodes.ACC_PRIVATE
                "protected" -> Opcodes.ACC_PROTECTED
                "final" -> Opcodes.ACC_FINAL
                "abstract" -> Opcodes.ACC_ABSTRACT
                "synthetic" -> Opcodes.ACC_SYNTHETIC
                else -> return@all false
            }
            val present = access and flag != 0
            if (negated) !present else present
        }

        private fun matchesKind(access: Int): Boolean = when (classKind) {
            "class" -> access and Opcodes.ACC_INTERFACE == 0
            "interface" -> access and Opcodes.ACC_INTERFACE != 0
            "enum" -> access and Opcodes.ACC_ENUM != 0
            else -> false
        }

        private fun matchingSuperclass(owner: BytecodeClass, bytecode: BytecodeInventory): String? {
            val visited = mutableSetOf<String>()
            var parentName = owner.superName
            while (parentName != null && visited.add(parentName)) {
                if (matchesClassPattern(ancestorPattern, parentName)) return parentName
                parentName = bytecode.hierarchyClasses[parentName]?.superName
            }
            return null
        }

        private fun matchingInterface(owner: BytecodeClass, bytecode: BytecodeInventory): String? {
            val pending = ArrayDeque<String>()
            val visitedClasses = mutableSetOf<String>()
            var current: BytecodeClass? = owner
            while (current != null && visitedClasses.add(current.internalName)) {
                current.interfaces.forEach(pending::addLast)
                current = current.superName?.let(bytecode.hierarchyClasses::get)
            }
            val visitedInterfaces = mutableSetOf<String>()
            while (pending.isNotEmpty()) {
                val interfaceName = pending.removeFirst()
                if (!visitedInterfaces.add(interfaceName)) continue
                if (matchesClassPattern(ancestorPattern, interfaceName)) return interfaceName
                bytecode.hierarchyClasses[interfaceName]?.interfaces?.forEach(pending::addLast)
            }
            return null
        }
    }

    private companion object {
        val WHITESPACE = Regex("\\s+")
        val HIERARCHY_RULE = Regex(
            """(?m)^\s*(-keep(?:names)?(?:,[a-z]+)*)\s+((?:(?:!?[a-z]+|@\S+)\s+)*)""" +
                """(class|interface|enum)\s+(\S+)\s+(extends|implements)\s+([^\s,{]+)""",
        )
        val CLASS_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_.$*?]*(?:\\.[A-Za-z0-9_.$*?]+)*|\\*\\*?")
        val SUPPORTED_ACCESS_TOKENS = setOf(
            "public",
            "private",
            "protected",
            "final",
            "abstract",
            "synthetic",
            "!public",
            "!private",
            "!protected",
            "!final",
            "!abstract",
            "!synthetic",
        )

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
