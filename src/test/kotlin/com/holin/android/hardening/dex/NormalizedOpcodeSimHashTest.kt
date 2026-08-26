package com.holin.android.hardening.dex

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NormalizedOpcodeSimHashTest {
    @Test
    fun `standard 64 bit signatures match known normalized opcode vectors`() {
        assertEquals("0000000000000000", NormalizedOpcodeSimHash.signatureHex(emptyList()))
        assertEquals(
            "c852e5e2d46e0401",
            NormalizedOpcodeSimHash.signatureHex(listOf("const", "return")),
        )
        assertEquals(
            "e9922343aff408fa",
            NormalizedOpcodeSimHash.signatureHex(
                listOf("const", "move", "field-get", "invoke", "return"),
            ),
        )
        assertEquals(
            "889221000f640072",
            NormalizedOpcodeSimHash.signatureHex(
                listOf("const", "move", "field-get", "invoke", "return", "goto"),
            ),
        )
    }

    @Test
    fun `minimum distance accepts four bits and rejects three bits`() {
        val distanceThreeLeft = listOf(
            "move", "field-put", "goto", "field-get", "invoke", "field-put", "goto", "return",
            "field-get", "field-put", "invoke", "field-get", "return", "nop", "if", "invoke",
            "move", "if", "invoke", "field-put",
        )
        val distanceThreeRight = distanceThreeLeft.toMutableList().apply { this[0] = "nop" }
        val distanceFourLeft = listOf(
            "field-put", "move", "goto", "move", "nop", "invoke", "if", "nop", "goto", "move",
            "new", "nop", "move", "field-get", "goto", "new", "field-put", "field-get", "if", "invoke",
        )
        val distanceFourRight = distanceFourLeft.toMutableList().apply { this[17] = "goto" }

        assertEquals(3, NormalizedOpcodeSimHash.distance(distanceThreeLeft, distanceThreeRight))
        assertEquals(4, NormalizedOpcodeSimHash.distance(distanceFourLeft, distanceFourRight))
        assertFalse(NormalizedOpcodeSimHash.meetsMinimum(distanceThreeLeft, distanceThreeRight, 4))
        assertTrue(NormalizedOpcodeSimHash.meetsMinimum(distanceFourLeft, distanceFourRight, 4))
    }
}
