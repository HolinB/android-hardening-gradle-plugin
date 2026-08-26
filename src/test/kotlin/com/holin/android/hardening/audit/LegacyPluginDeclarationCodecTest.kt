package com.holin.android.hardening.audit

import com.holin.android.hardening.LegacyPluginDeclaration
import kotlin.test.Test
import kotlin.test.assertEquals

class LegacyPluginDeclarationCodecTest {
    @Test
    fun `encoding is deterministic and round trips sorted portable paths`() {
        val declaration = LegacyPluginDeclaration(
            "fixture",
            "com.example.legacy",
            "1.2.3",
            listOf("z.gradle.kts", "a.gradle.kts"),
            listOf("mapping/z.txt", "mapping/a.txt"),
        )
        val reordered = declaration.copy(
            configurationInputs = declaration.configurationInputs.reversed(),
            mappingPaths = declaration.mappingPaths.reversed(),
        )

        val encoded = LegacyPluginDeclarationCodec.encode(declaration)

        assertEquals(encoded, LegacyPluginDeclarationCodec.encode(reordered))
        assertEquals(
            declaration.copy(
                configurationInputs = declaration.configurationInputs.sorted(),
                mappingPaths = declaration.mappingPaths.sorted(),
            ),
            LegacyPluginDeclarationCodec.decode(encoded),
        )
    }
}
