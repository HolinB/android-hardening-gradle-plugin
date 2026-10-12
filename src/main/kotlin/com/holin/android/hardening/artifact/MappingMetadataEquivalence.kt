package com.holin.android.hardening.artifact

import com.holin.android.hardening.components.PreR8Relocation

/** Proves canonical source identities before the compiler mapping is detached from the bundle. */
object MappingMetadataEquivalence {
    const val PATH = "BUNDLE-METADATA/com.android.tools.build.obfuscation/proguard.map"
    fun verifyCanonical(entries: Map<String, ByteArray>, aliases: Map<String, String>, canonical: String) {
        if (aliases.isEmpty()) return
        val original = requireNotNull(entries[PATH]) { "relocated bundle is missing its R8 mapping metadata" }
        val bytes = canonical.toByteArray(Charsets.UTF_8)
        verify(PATH, PATH, original, bytes, aliases)
    }
    fun verify(oldPath: String, newPath: String, before: ByteArray, after: ByteArray, aliases: Map<String, String>) {
        require(oldPath == PATH && newPath == PATH && aliases.isNotEmpty())
        require(aliases.values.toSet().size == aliases.size && aliases.keys.intersect(aliases.values.toSet()).isEmpty())
        val original = before.toString(Charsets.UTF_8)
        val canonical = after.toString(Charsets.UTF_8)
        require(original.toByteArray(Charsets.UTF_8).contentEquals(before) && canonical.toByteArray(Charsets.UTF_8).contentEquals(after))
        val inverse = aliases.entries.associate { it.value to it.key }
        require(PreR8Relocation.rewriteMappingLeft(original, inverse) == canonical) { "embedded mapping differs from canonical source mapping" }
        require(PreR8Relocation.rewriteMappingLeft(canonical, aliases) == original) { "embedded mapping inverse proof failed" }
    }
}
