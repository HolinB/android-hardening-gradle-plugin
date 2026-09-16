package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal object SafeUnreachablePayloadContract {
    val REGISTER_BEARING_OPCODES = listOf(
        Opcode.CONST_4,
        Opcode.MOVE,
        Opcode.NEG_INT,
        Opcode.NOT_INT,
        Opcode.ADD_INT_2ADDR,
        Opcode.SUB_INT_2ADDR,
        Opcode.MUL_INT_2ADDR,
        Opcode.AND_INT_2ADDR,
        Opcode.OR_INT_2ADDR,
        Opcode.XOR_INT_2ADDR,
        Opcode.SHL_INT_2ADDR,
        Opcode.SHR_INT_2ADDR,
        Opcode.USHR_INT_2ADDR,
    )
    val REGISTER_BEARING_OPCODE_SET = REGISTER_BEARING_OPCODES.toSet() + Opcode.CONST_STRING_JUMBO

    fun isValidPayload(instructions: List<Instruction>, registerCount: Int): Boolean {
        return isValidPayloadChunks(listOf(instructions), registerCount)
    }

    fun isValidPayloadChunks(chunks: List<List<Instruction>>, registerCount: Int): Boolean {
        if (chunks.isEmpty() || chunks.any(List<Instruction>::isEmpty)) return false
        if (registerCount == 0) return chunks.flatten().all { it.opcode == Opcode.NOP }
        if (chunks.any { it.first().opcode != Opcode.CONST_4 }) return false
        val instructions = chunks.flatten()
        if (!instructions.all(::isValidRegisterInstruction)) return false
        val markers = instructions.mapNotNull(::marker)
        return markers.size == MarkerCategory.values().size &&
            markers.map(Pair<MarkerCategory, String>::first).toSet() == MarkerCategory.values().toSet() &&
            markers.map(Pair<MarkerCategory, String>::second).toSet().size == markers.size
    }

    fun markerValues(salt: ByteArray, methodId: String): List<String> = MarkerCategory.values().map { category ->
        if (category == MarkerCategory.EMPTY) "" else category.prefix + markerBody(
            salt = salt,
            methodId = methodId,
            category = category,
            length = category.length - category.prefix.length,
        )
    }

    fun hasExpectedMarkerValues(chunks: List<List<Instruction>>, expectedValues: List<String>): Boolean {
        val actualValues = chunks.flatten().mapNotNull(::marker).map(Pair<MarkerCategory, String>::second)
        return actualValues.size == expectedValues.size && actualValues.toSet() == expectedValues.toSet()
    }

    private fun isValidRegisterInstruction(instruction: Instruction): Boolean {
        if (instruction.opcode !in REGISTER_BEARING_OPCODE_SET) return false
        return when (instruction.opcode) {
            Opcode.CONST_4 -> (instruction as? OneRegisterInstruction)?.registerA == 0
            Opcode.CONST_STRING_JUMBO -> marker(instruction) != null
            else -> (instruction as? TwoRegisterInstruction)?.let {
                it.registerA == 0 && it.registerB == 0
            } == true
        }
    }

    private fun marker(instruction: Instruction): Pair<MarkerCategory, String>? {
        if (instruction.opcode != Opcode.CONST_STRING_JUMBO) return null
        if ((instruction as? OneRegisterInstruction)?.registerA != 0) return null
        val value = ((instruction as? ReferenceInstruction)?.reference as? StringReference)?.string ?: return null
        val category = MarkerCategory.values().singleOrNull { it.matches(value) } ?: return null
        return category to value
    }

    private fun markerBody(
        salt: ByteArray,
        methodId: String,
        category: MarkerCategory,
        length: Int,
    ): String = buildString(length) {
        var block = 0
        while (this.length < length) {
            val digest = MessageDigest.getInstance("SHA-256").apply {
                update(MARKER_DOMAIN)
                updateInt(salt.size)
                update(salt)
                val method = methodId.toByteArray(StandardCharsets.UTF_8)
                updateInt(method.size)
                update(method)
                update(category.name.toByteArray(StandardCharsets.US_ASCII))
                updateInt(block++)
            }.digest()
            digest.forEach { byte ->
                if (this.length < length) append(MARKER_ALPHABET[byte.toInt() and 0x1f])
            }
        }
    }

    private fun MessageDigest.updateInt(value: Int) {
        update(ByteBuffer.allocate(Int.SIZE_BYTES).order(ByteOrder.BIG_ENDIAN).putInt(value).array())
    }

    private enum class MarkerCategory(val length: Int, val prefix: String) {
        EMPTY(0, ""),
        SHORT(8, "SLH1S"),
        MEDIUM(9, "SLH1M:"),
        LONG(33, "SLH1L:"),
        VERY_LONG(129, "SLH1V:"),
        ;

        fun matches(value: String): Boolean = when (this) {
            EMPTY -> value.isEmpty()
            else -> value.length == length && value.startsWith(prefix) &&
                value.drop(prefix.length).all(MARKER_ALPHABET::contains)
        }
    }

    private val MARKER_DOMAIN =
        "com.holin.android.hardening/1.3.0/unreachable-string-marker/v1\u0000".toByteArray(StandardCharsets.US_ASCII)
    private const val MARKER_ALPHABET = "0123456789abcdefghijklmnopqrstuv"
}
