package com.holin.android.hardening.audit

import com.holin.android.hardening.LegacyPluginDeclaration
import java.util.Base64
import java.util.Collections

object LegacyPluginDeclarationCodec {
    fun encode(declaration: LegacyPluginDeclaration): String = listOf(
        declaration.name,
        declaration.pluginId,
        declaration.expectedVersion,
        declaration.configurationInputs.sorted().joinToString(LIST_SEPARATOR),
        declaration.mappingPaths.sorted().joinToString(LIST_SEPARATOR),
    ).joinToString(FIELD_SEPARATOR) { field ->
        Base64.getUrlEncoder().withoutPadding().encodeToString(field.toByteArray(Charsets.UTF_8))
    }

    fun decode(value: String): LegacyPluginDeclaration {
        val fields = value.split(FIELD_SEPARATOR).map { field ->
            String(Base64.getUrlDecoder().decode(field), Charsets.UTF_8)
        }
        require(fields.size == 5) { "invalid legacy plugin declaration" }
        return LegacyPluginDeclaration(
            fields[0],
            fields[1],
            fields[2],
            splitList(fields[3]),
            splitList(fields[4]),
        )
    }

    private fun splitList(value: String): List<String> = Collections.unmodifiableList(
        if (value.isEmpty()) emptyList() else value.split(LIST_SEPARATOR),
    )

    private const val FIELD_SEPARATOR = "."
    private const val LIST_SEPARATOR = "\u001f"
}
