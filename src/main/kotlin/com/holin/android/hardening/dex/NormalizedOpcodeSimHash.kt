package com.holin.android.hardening.dex

import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

internal object NormalizedOpcodeSimHash {
    fun signature(instructions: Iterable<Instruction>): Long =
        signature(CommonOpcodeShingles.tokens(instructions))

    fun signature(normalizedOpcodeTokens: List<String>): Long {
        val shingles = CommonOpcodeShingles.shingles(normalizedOpcodeTokens)
        if (shingles.isEmpty()) return 0L
        val weights = IntArray(Long.SIZE_BITS)
        shingles.sorted().forEach { shingle ->
            val hash = ByteBuffer.wrap(
                MessageDigest.getInstance("SHA-256")
                    .digest(shingle.toByteArray(StandardCharsets.UTF_8)),
                0,
                Long.SIZE_BYTES,
            ).order(ByteOrder.BIG_ENDIAN).long
            repeat(Long.SIZE_BITS) { bit ->
                weights[bit] += if (hash and (1L shl bit) != 0L) 1 else -1
            }
        }
        return weights.foldIndexed(0L) { bit, result, weight ->
            if (weight > 0) result or (1L shl bit) else result
        }
    }

    fun signatureHex(normalizedOpcodeTokens: List<String>): String =
        java.lang.Long.toUnsignedString(signature(normalizedOpcodeTokens), 16).padStart(16, '0')

    fun distance(before: Iterable<Instruction>, after: Iterable<Instruction>): Int =
        java.lang.Long.bitCount(signature(before) xor signature(after))

    fun distance(before: List<String>, after: List<String>): Int =
        java.lang.Long.bitCount(signature(before) xor signature(after))

    fun meetsMinimum(before: List<String>, after: List<String>, minimumDistance: Int): Boolean {
        require(minimumDistance in 0..Long.SIZE_BITS) { "minimum SimHash distance must be in 0..64" }
        return distance(before, after) >= minimumDistance
    }
}
