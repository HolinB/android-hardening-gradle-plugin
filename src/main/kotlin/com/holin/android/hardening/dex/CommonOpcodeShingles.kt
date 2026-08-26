package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import java.util.Locale

internal object CommonOpcodeShingles {
    private const val WIDTH = 5

    fun tokens(instructions: Iterable<Instruction>): List<String> = instructions.map { instruction ->
        family(instruction.opcode.name)
    }

    fun shingles(tokens: List<String>): Set<String> {
        if (tokens.isEmpty()) return emptySet()
        if (tokens.size < WIDTH) return setOf(tokens.joinToString(SEPARATOR))
        return (0..tokens.size - WIDTH).mapTo(linkedSetOf()) { index ->
            tokens.subList(index, index + WIDTH).joinToString(SEPARATOR)
        }
    }

    fun similarity(oldTokens: List<String>, newTokens: List<String>): Double {
        val old = shingles(oldTokens)
        val new = shingles(newTokens)
        if (old.isEmpty() && new.isEmpty()) return 1.0
        val union = old union new
        return if (union.isEmpty()) 1.0 else (old intersect new).size.toDouble() / union.size
    }

    fun effectiveness(oldTokens: List<String>, newTokens: List<String>): Double {
        val old = shingles(oldTokens)
        if (old.isEmpty()) return 0.0
        val retained = (old intersect shingles(newTokens)).size
        return 1.0 - retained.toDouble() / old.size
    }

    private fun family(raw: String): String {
        val name = raw.lowercase(Locale.ROOT).substringBefore('/')
        OPCODE_FAMILIES.firstOrNull { (prefix, _) -> name.startsWith(prefix) }?.let { return it.second }
        return name.substringBefore('-')
    }

    private const val SEPARATOR = "\u001f"
    private val OPCODE_FAMILIES = listOf(
        "invoke" to "invoke",
        "const" to "const",
        "move" to "move",
        "if-" to "if",
        "goto" to "goto",
        "return" to "return",
        "iget" to "field-get",
        "sget" to "field-get",
        "iput" to "field-put",
        "sput" to "field-put",
        "aget" to "array-get",
        "aput" to "array-put",
        "new-" to "new",
        "packed-switch" to "switch",
        "sparse-switch" to "switch",
    )
}
