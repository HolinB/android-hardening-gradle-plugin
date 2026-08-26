package com.holin.android.hardening.r8

import com.holin.android.hardening.state.Sha256

/**
 * Produces the opt-in replacement for the app's broad legacy ProGuard file.
 *
 * This deliberately recognizes only known blanket rules. Everything else is
 * retained verbatim in meaning, pending a later contract-specific rule pass.
 */
object HardeningRulesFilter {
    fun filter(
        source: String,
        ownedPackageRoots: Set<String> = emptySet(),
        preserveExactRules: String = "",
        additionalRules: String = "",
    ): HardeningRulesFilterResult {
        val validatedOwnedPackageRoots = ownedPackageRoots.mapTo(linkedSetOf()) { root ->
            require(PACKAGE_ROOT.matches(root)) { "owned package root is malformed: $root" }
            root
        }
        val preservedBlocks = parse(preserveExactRules)
        val preservedRuleKeys = preservedBlocks.filter { it.directive != null }
            .mapTo(linkedSetOf()) { block -> normalize(block.body) }
        val blocks = parse(source)
        val decisions = blocks.mapIndexed { ordinal, block ->
            val reason = classify(block.directive, block.body, validatedOwnedPackageRoots, preservedRuleKeys)
            RuleDecision(
                ordinal = ordinal,
                directive = block.directive,
                action = if (reason.removes) RuleDecisionAction.REMOVE else RuleDecisionAction.PRESERVE,
                reason = reason,
                sourceSha256 = Sha256.hex(block.text.toByteArray(Charsets.UTF_8)),
                normalizedSha256 = Sha256.hex(normalize(block.text).toByteArray(Charsets.UTF_8)),
            )
        }
        val retainedRules = normalize(
            blocks.zip(decisions)
                .filter { (_, decision) -> decision.action == RuleDecisionAction.PRESERVE }
                .joinToString(separator = "") { (block, _) -> block.text },
        )
        val retainedKeys = parse(retainedRules).filter { it.directive != null }
            .mapTo(linkedSetOf()) { block -> normalize(block.body) }
        val missingPreserved = preservedBlocks.filter { block ->
            block.directive == null || normalize(block.body) !in retainedKeys
        }.joinToString(separator = "", transform = RuleBlock::text)
        val effectiveRules = normalize(
            retainedRules + missingPreserved + additionalRules + PORTABLE_RUNTIME_SAFETY_RULES,
        )
        return HardeningRulesFilterResult(
            effectiveRules = effectiveRules,
            manifest = HardeningRuleManifest(
                schemaVersion = SCHEMA_VERSION,
                sourceSha256 = Sha256.hex(source.toByteArray(Charsets.UTF_8)),
                normalizedSourceSha256 = Sha256.hex(normalize(source).toByteArray(Charsets.UTF_8)),
                outputSha256 = Sha256.hex(effectiveRules.toByteArray(Charsets.UTF_8)),
                normalizedOutputSha256 = Sha256.hex(normalize(effectiveRules).toByteArray(Charsets.UTF_8)),
                decisions = decisions,
            ),
        )
    }

    private fun parse(source: String): List<RuleBlock> {
        val lines = source.replace("\r\n", "\n").replace('\r', '\n').split('\n')
        val blocks = mutableListOf<RuleBlock>()
        val prefix = mutableListOf<String>()
        var body: MutableList<String>? = null
        var braceDepth = 0
        var awaitingOpeningBrace = false

        fun closeCurrent() {
            val current = requireNotNull(body)
            val text = (prefix + current).joinToString("\n", postfix = "\n")
            val directive = current.first().trim()
            blocks += RuleBlock(text, directive, current.joinToString("\n"))
            prefix.clear()
            body = null
            awaitingOpeningBrace = false
        }

        lines.forEachIndexed { index, line ->
            val current = body
            if (current != null) {
                current += line
                braceDepth += braceDelta(line)
                require(braceDepth >= 0) { "unbalanced ProGuard braces near: ${current.first()}" }
                if (awaitingOpeningBrace && line.trimStart().startsWith("{")) {
                    awaitingOpeningBrace = false
                }
                if (braceDepth == 0 && !awaitingOpeningBrace) closeCurrent()
            } else if (line.trimStart().startsWith('-')) {
                body = mutableListOf(line)
                braceDepth = braceDelta(line)
                require(braceDepth >= 0) { "unbalanced ProGuard braces near: $line" }
                awaitingOpeningBrace =
                    braceDepth == 0 && !containsBrace(line) && nextSignificantLineStartsBody(lines, index)
                if (braceDepth == 0 && !awaitingOpeningBrace) closeCurrent()
            } else {
                prefix += line
            }
        }
        require(body == null) { "unterminated ProGuard rule: ${body!!.first()}" }
        if (prefix.isNotEmpty()) {
            blocks += RuleBlock(prefix.joinToString("\n", postfix = "\n"), null, "")
        }
        return blocks
    }

    private fun nextSignificantLineStartsBody(lines: List<String>, directiveIndex: Int): Boolean {
        return lines.drop(directiveIndex + 1)
            .firstOrNull { line -> line.isNotBlank() && !line.trimStart().startsWith("#") }
            ?.trimStart()
            ?.startsWith("{") == true
    }

    private fun containsBrace(line: String): Boolean {
        val code = line.substringBefore('#')
        return code.contains('{') || code.contains('}')
    }

    private fun braceDelta(line: String): Int {
        val code = line.substringBefore('#')
        return code.count { it == '{' } - code.count { it == '}' }
    }

    private fun classify(
        directive: String?,
        body: String,
        ownedPackageRoots: Set<String>,
        preservedRuleKeys: Set<String>,
    ): RuleDecisionReason {
        if (directive == null) return RuleDecisionReason.UNKNOWN_RULE
        if (normalize(body) in preservedRuleKeys) return RuleDecisionReason.PRESERVED_EXACT_RULE
        val full = "$directive\n$body"
        return when {
            isKeepDirective(directive) && FULL_ANDROIDX.containsMatchIn(full) -> RuleDecisionReason.BROAD_ANDROIDX
            isKeepDirective(directive) && FULL_GOOGLE.containsMatchIn(full) -> RuleDecisionReason.BROAD_GOOGLE
            isOwnedPackageBlanket(directive, body, ownedPackageRoots) -> RuleDecisionReason.BROAD_OWNED_PACKAGE
            isWildcardSubclassBlanket(directive, body, ownedPackageRoots) ->
                RuleDecisionReason.BROAD_WILDCARD_SUBCLASS
            isOwnedKotlinBlanket(directive, full, ownedPackageRoots) -> RuleDecisionReason.BROAD_OWNED_PACKAGE
            BROAD_SERIALIZABLE_CLASS_NAMES.matches(directive) -> RuleDecisionReason.BROAD_SERIALIZABLE_CLASS_NAMES
            isBroadGsonImplementationClassName(directive, body) ->
                RuleDecisionReason.BROAD_GSON_IMPLEMENTATION_CLASS_NAMES
            isBroadParcelableClassName(body) -> RuleDecisionReason.BROAD_PARCELABLE_CLASS_NAMES
            isKeepDirective(directive) && R_OR_BINDING.containsMatchIn(full) -> RuleDecisionReason.BROAD_R_OR_BINDING
            isGlobalFields(directive, body) -> RuleDecisionReason.GLOBAL_FIELDS
            isGlobalViewOrComponent(directive, body) -> RuleDecisionReason.GLOBAL_VIEW_OR_COMPONENT
            else -> RuleDecisionReason.UNKNOWN_RULE
        }
    }

    private fun isKeepDirective(directive: String): Boolean = directive.startsWith("-keep")

    private fun isOwnedKotlinBlanket(
        directive: String,
        full: String,
        ownedPackageRoots: Set<String>,
    ): Boolean {
        if (!isKeepDirective(directive)) return false
        val packageRoot = OWNED_KOTLIN_BLANKET.find(full)?.groupValues?.get(1) ?: return false
        return ownsPackage(packageRoot, ownedPackageRoots)
    }

    private fun isOwnedPackageBlanket(
        directive: String,
        body: String,
        ownedPackageRoots: Set<String>,
    ): Boolean {
        if (!isKeepDirective(directive)) return false
        val packageRoot = OWNED_PACKAGE_BLANKET.matchEntire(body.trim())?.groupValues?.get(1) ?: return false
        return ownsPackage(packageRoot, ownedPackageRoots)
    }

    private fun ownsPackage(packageRoot: String, ownedPackageRoots: Set<String>): Boolean =
        ownedPackageRoots.any { root ->
            root == packageRoot || root.startsWith("$packageRoot.") || packageRoot.startsWith("$root.")
        }

    private fun isWildcardSubclassBlanket(
        directive: String,
        body: String,
        ownedPackageRoots: Set<String>,
    ): Boolean {
        if (!isKeepDirective(directive)) return false
        val normalized = body.trim()
        val wildcardBase = WILDCARD_SUBCLASS_BLANKET.matchEntire(normalized)?.groupValues?.get(1)
        if (wildcardBase != null) return ownsPackage(wildcardBase, ownedPackageRoots)
        val exactBase = OWNED_EXACT_SUBCLASS_BLANKET.matchEntire(normalized)?.groupValues?.get(1) ?: return false
        val basePackage = exactBase.substringBeforeLast('.', "")
        return basePackage.isNotEmpty() && ownsPackage(basePackage, ownedPackageRoots)
    }

    private fun isBroadGsonImplementationClassName(directive: String, body: String): Boolean =
        BROAD_GSON_IMPLEMENTATION_CLASS_NAMES.matches(directive) && body.trim() == directive

    private fun isBroadParcelableClassName(body: String): Boolean =
        BROAD_PARCELABLE_CLASS_NAMES.matches(body.trim())

    private fun isGlobalFields(directive: String, body: String): Boolean =
        isKeepDirective(directive) && directive.contains("class *") && body.lineSequence().any { line ->
            line.trim().matches(Regex("(?:public |protected |private |!transient )?<fields>;"))
        }

    private fun isGlobalViewOrComponent(directive: String, body: String): Boolean {
        if (!isKeepDirective(directive) || !directive.contains("class *")) return false
        if (body.contains("<init>(android.content.Context, android.util.AttributeSet)")) return true
        return GLOBAL_COMPONENT_OR_VIEW.containsMatchIn("$directive\n$body")
    }

    private fun normalize(text: String): String {
        val normalizedLines = text.replace("\r\n", "\n").replace('\r', '\n')
            .split('\n')
            .map(String::trimEnd)
            .toMutableList()
        while (normalizedLines.firstOrNull()?.isBlank() == true) normalizedLines.removeFirst()
        while (normalizedLines.lastOrNull()?.isBlank() == true) normalizedLines.removeLast()
        return if (normalizedLines.isEmpty()) "" else normalizedLines.joinToString("\n", postfix = "\n")
    }

    private val RuleDecisionReason.removes: Boolean
        get() = this !in setOf(RuleDecisionReason.UNKNOWN_RULE, RuleDecisionReason.PRESERVED_EXACT_RULE)

    private data class RuleBlock(val text: String, val directive: String?, val body: String)

    private const val SCHEMA_VERSION = 1
    private val PORTABLE_RUNTIME_SAFETY_RULES = """

        # R8 can otherwise move a SuspendLambda away from a late synthetic caller while
        # leaving their optimized bridge package-private, which fails access checks on ART.
        -keep,allowobfuscation,allowshrinking class * extends kotlin.coroutines.jvm.internal.SuspendLambda {
            *;
        }
    """.trimIndent() + "\n"
    private val FULL_ANDROIDX = Regex("\\bandroidx\\.\\*\\*")
    private val FULL_GOOGLE = Regex("\\bcom\\.google\\.\\*\\*")
    private val OWNED_PACKAGE_BLANKET = Regex(
        """-keep\s+(?:class|interface)\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)(?:\.\*\*|\*\*)\s*\{\s*\*;\s*\}""",
    )
    private val PACKAGE_ROOT = Regex("[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)*")
    private val OWNED_KOTLIN_BLANKET = Regex(
        """@kotlin\.Metadata\s+class\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\.\*\*""",
    )
    private val WILDCARD_SUBCLASS_BLANKET = Regex(
        """-keep\s+public\s+class\s+\*\s+extends\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\.\*\s*""",
    )
    private val OWNED_EXACT_SUBCLASS_BLANKET = Regex(
        """-keep\s+public\s+class\s+\*\s+extends\s+([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*""",
    )
    private val BROAD_SERIALIZABLE_CLASS_NAMES = Regex(
        """-keepnames\s+class\s+\*\s+implements\s+java\.io\.Serializable\s*""",
    )
    private val BROAD_GSON_IMPLEMENTATION_CLASS_NAMES = Regex(
        """-keep\s+class\s+\*\s+(?:extends\s+com\.google\.gson\.(?:reflect\.TypeToken|TypeAdapter)|implements\s+com\.google\.gson\.(?:TypeAdapterFactory|JsonSerializer|JsonDeserializer))\s*""",
    )
    private val BROAD_PARCELABLE_CLASS_NAMES = Regex(
        """-keep[ \t]+class[ \t]+\*[ \t]+implements[ \t]+android\.os\.Parcelable[ \t\n]*\{[ \t\n]*public[ \t]+static[ \t]+final[ \t]+android\.os\.Parcelable\${'$'}Creator[ \t]+\*;[ \t\n]*\}""",
    )
    private val R_OR_BINDING = Regex("(?:\\*\\*\\.R\\$\\*|\\.R\\$\\*|\\*Binding(?:Impl)?\\b)")
    private val GLOBAL_COMPONENT_OR_VIEW = Regex(
        "extends\\s+(?:android\\.app\\.(?:Activity|Fragment|Application|Service|backup\\.BackupAgentHelper)|" +
            "android\\.content\\.(?:BroadcastReceiver|ContentProvider)|android\\.preference\\.Preference|" +
            "android\\.view\\.View|androidx\\.[^\\s{]+)",
    )
}
