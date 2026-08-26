package com.holin.android.hardening.code

import kotlin.test.Test
import kotlin.test.assertEquals

class OwnedClassStringRulesRendererTest {
    @Test
    fun `renderer scopes deterministic class string adaptation to exact owned source classes`() {
        assertEquals(
            """
            -adaptclassstrings com.example.Alpha,com.example.Alpha${'$'}*
            -adaptclassstrings com.example.beta.Zed,com.example.beta.Zed${'$'}*

            """.trimIndent(),
            OwnedClassStringRulesRenderer().render(
                listOf("Lcom/example/beta/Zed;", "Lcom/example/Alpha;", "Lcom/example/Alpha;"),
            ),
        )
    }
}
