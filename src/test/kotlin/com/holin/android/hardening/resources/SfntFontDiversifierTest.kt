package com.holin.android.hardening.resources

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SfntFontDiversifierTest {
    @Test
    fun `rejects fonts with active digital signatures`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            SfntFontDiversifier().diversify(
                signedSfntFont(),
                ByteArray(32) { 7 },
                "base/res/font/signed.ttf",
            )
        }

        assertTrue(failure.message.orEmpty().contains("DSIG"))
    }

    private fun signedSfntFont(): ByteArray {
        val tables = listOf(
            Table(HEAD_TAG, ByteArray(12).also { ByteBuffer.wrap(it).order(ByteOrder.BIG_ENDIAN).putInt(0, 0x00010000) }),
            Table(DSIG_TAG, ByteArray(8).also { bytes ->
                ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).apply {
                    putInt(0, 1)
                    putShort(4, 1)
                    putShort(6, 0)
                }
            }),
        )
        val directoryEnd = 12 + tables.size * 16
        var dataOffset = align4(directoryEnd)
        val offsets = tables.map { table ->
            val offset = dataOffset
            dataOffset = align4(dataOffset + table.bytes.size)
            offset
        }
        val output = ByteArray(dataOffset)
        val buffer = ByteBuffer.wrap(output).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(0, 0x00010000)
        buffer.putShort(4, tables.size.toShort())
        buffer.putShort(6, 32)
        buffer.putShort(8, 1)
        buffer.putShort(10, 0)
        tables.forEachIndexed { index, table ->
            val record = 12 + index * 16
            buffer.putInt(record, table.tag)
            buffer.putInt(record + 4, checksum(table.bytes).toInt())
            buffer.putInt(record + 8, offsets[index])
            buffer.putInt(record + 12, table.bytes.size)
            table.bytes.copyInto(output, offsets[index])
        }
        val headOffset = offsets[tables.indexOfFirst { it.tag == HEAD_TAG }]
        buffer.putInt(headOffset + 8, ((FONT_CHECKSUM_MAGIC - checksum(output)) and UINT32_MASK).toInt())
        return output
    }

    private fun checksum(bytes: ByteArray): Long {
        var sum = 0L
        var offset = 0
        while (offset < bytes.size) {
            var word = 0L
            repeat(4) { index ->
                word = word shl 8
                if (offset + index < bytes.size) word = word or (bytes[offset + index].toLong() and 0xffL)
            }
            sum = (sum + word) and UINT32_MASK
            offset += 4
        }
        return sum
    }

    private fun align4(value: Int): Int = (value + 3) and -4

    private data class Table(val tag: Int, val bytes: ByteArray)

    private companion object {
        const val HEAD_TAG = 0x68656164
        const val DSIG_TAG = 0x44534947
        const val FONT_CHECKSUM_MAGIC = 0xb1b0afbaL
        const val UINT32_MASK = 0xffffffffL
    }
}
