package com.holin.android.hardening.resources

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

class SfntFontDiversifier {
    fun diversify(source: ByteArray, contentSalt: ByteArray, context: String): ByteArray {
        require(contentSalt.isNotEmpty()) { "SFNT diversification salt must not be empty" }
        require(context.isNotBlank()) { "SFNT diversification context must not be blank" }
        val original = parse(source)
        requireNoActiveDigitalSignatures(original)
        require(original.tables.none { it.tag == MARKER_TAG }) {
            "SFNT font already contains the hardening diversification table"
        }
        val output = encode(
            original.scalerType,
            original.tables + SfntTable(MARKER_TAG, markerPayload(source, contentSalt, context)),
        )
        verify(source, output, contentSalt, context)
        return output
    }

    fun verify(originalBytes: ByteArray, diversifiedBytes: ByteArray, contentSalt: ByteArray, context: String) {
        require(contentSalt.isNotEmpty()) { "SFNT verification salt must not be empty" }
        require(context.isNotBlank()) { "SFNT verification context must not be blank" }
        val original = parse(originalBytes)
        requireNoActiveDigitalSignatures(original)
        val diversified = parse(diversifiedBytes)
        require(original.scalerType == diversified.scalerType) { "SFNT scaler type changed" }
        require(diversified.tables.size == original.tables.size + 1) { "SFNT table count changed unexpectedly" }
        val originalByTag = original.tables.associateBy(SfntTable::tag)
        val diversifiedByTag = diversified.tables.associateBy(SfntTable::tag)
        require(diversifiedByTag.keys == originalByTag.keys + MARKER_TAG) {
            "SFNT table set changed outside the diversification table"
        }
        originalByTag.forEach { (tag, before) ->
            val after = requireNotNull(diversifiedByTag[tag]) { "SFNT table disappeared during diversification" }
            val unchanged = if (tag == HEAD_TAG) {
                normalizedHead(before.bytes).contentEquals(normalizedHead(after.bytes))
            } else {
                before.bytes.contentEquals(after.bytes)
            }
            require(unchanged) { "SFNT table ${tagName(tag)} changed semantically" }
        }
        val marker = requireNotNull(diversifiedByTag[MARKER_TAG]) { "SFNT diversification table is missing" }
        require(marker.bytes.contentEquals(markerPayload(originalBytes, contentSalt, context))) {
            "SFNT diversification table does not match the invocation salt"
        }
    }

    private fun parse(bytes: ByteArray): SfntFont {
        require(bytes.size >= OFFSET_TABLE_BYTES) { "SFNT font is truncated" }
        val scalerType = readUInt32(bytes, 0).toInt()
        require(scalerType in SUPPORTED_SCALER_TYPES) { "SFNT scaler type is unsupported" }
        val tableCount = readUInt16(bytes, 4)
        require(tableCount in 1..MAX_TABLE_COUNT) { "SFNT table count is invalid" }
        val directoryEnd = OFFSET_TABLE_BYTES + tableCount * TABLE_RECORD_BYTES
        require(directoryEnd <= bytes.size) { "SFNT table directory is truncated" }
        val expectedSearchRange = searchRange(tableCount)
        require(readUInt16(bytes, 6) == expectedSearchRange &&
            readUInt16(bytes, 8) == entrySelector(tableCount) &&
            readUInt16(bytes, 10) == tableCount * TABLE_RECORD_BYTES - expectedSearchRange) {
            "SFNT offset table search fields are invalid"
        }
        val tables = (0 until tableCount).map { index ->
            val record = OFFSET_TABLE_BYTES + index * TABLE_RECORD_BYTES
            val tag = readUInt32(bytes, record).toInt()
            val expectedChecksum = readUInt32(bytes, record + 4)
            val offset = checkedInt(readUInt32(bytes, record + 8), "SFNT table offset")
            val length = checkedInt(readUInt32(bytes, record + 12), "SFNT table length")
            require(offset % 4 == 0 && offset >= align4(directoryEnd)) { "SFNT table offset is invalid" }
            require(offset <= bytes.size && length <= bytes.size - offset) { "SFNT table range is invalid" }
            val payload = bytes.copyOfRange(offset, offset + length)
            val checksumBytes = if (tag == HEAD_TAG) normalizedHead(payload) else payload
            require(checksum(checksumBytes) == expectedChecksum) {
                "SFNT table ${tagName(tag)} checksum is invalid"
            }
            SfntTable(tag, payload, offset)
        }
        require(tables.map(SfntTable::tag).distinct().size == tables.size) { "SFNT table tags are duplicated" }
        val ranges = tables.filter { it.bytes.isNotEmpty() }.sortedBy(SfntTable::offset)
        ranges.zipWithNext().forEach { (left, right) ->
            require(left.offset + left.bytes.size <= right.offset) { "SFNT table ranges overlap" }
        }
        require(tables.singleOrNull { it.tag == HEAD_TAG }?.bytes?.size?.let { it >= HEAD_ADJUSTMENT_END } == true) {
            "SFNT head table is missing or truncated"
        }
        require(checksum(bytes) == FONT_CHECKSUM_MAGIC) { "SFNT whole-font checksum is invalid" }
        return SfntFont(scalerType, tables.map { it.copy(offset = 0) })
    }

    private fun encode(scalerType: Int, requestedTables: List<SfntTable>): ByteArray {
        require(requestedTables.size in 1..MAX_TABLE_COUNT) { "SFNT output table count is invalid" }
        require(requestedTables.map(SfntTable::tag).distinct().size == requestedTables.size) {
            "SFNT output table tags are duplicated"
        }
        val tables = requestedTables.sortedBy { it.tag.toUInt() }.map { table ->
            if (table.tag == HEAD_TAG) table.copy(bytes = normalizedHead(table.bytes)) else table
        }
        val directoryEnd = OFFSET_TABLE_BYTES + tables.size * TABLE_RECORD_BYTES
        var dataOffset = align4(directoryEnd)
        val laidOut = tables.map { table ->
            val result = table.copy(offset = dataOffset)
            dataOffset = align4(dataOffset + table.bytes.size)
            result
        }
        val output = ByteArray(dataOffset)
        val buffer = ByteBuffer.wrap(output).order(ByteOrder.BIG_ENDIAN)
        buffer.putInt(0, scalerType)
        buffer.putShort(4, tables.size.toShort())
        buffer.putShort(6, searchRange(tables.size).toShort())
        buffer.putShort(8, entrySelector(tables.size).toShort())
        buffer.putShort(10, (tables.size * TABLE_RECORD_BYTES - searchRange(tables.size)).toShort())
        laidOut.forEachIndexed { index, table ->
            val record = OFFSET_TABLE_BYTES + index * TABLE_RECORD_BYTES
            buffer.putInt(record, table.tag)
            buffer.putInt(record + 4, checksum(table.bytes).toInt())
            buffer.putInt(record + 8, table.offset)
            buffer.putInt(record + 12, table.bytes.size)
            table.bytes.copyInto(output, table.offset)
        }
        val head = laidOut.single { it.tag == HEAD_TAG }
        val adjustment = (FONT_CHECKSUM_MAGIC - checksum(output)) and UINT32_MASK
        buffer.putInt(head.offset + HEAD_ADJUSTMENT_OFFSET, adjustment.toInt())
        require(checksum(output) == FONT_CHECKSUM_MAGIC) { "SFNT output checksum could not be rebuilt" }
        return output
    }

    private fun requireNoActiveDigitalSignatures(font: SfntFont) {
        val dsig = font.tables.singleOrNull { it.tag == DSIG_TAG } ?: return
        require(dsig.bytes.size >= DSIG_HEADER_BYTES) { "SFNT DSIG table is truncated" }
        require(readUInt16(dsig.bytes, DSIG_SIGNATURE_COUNT_OFFSET) == 0) {
            "SFNT DSIG table contains active digital signatures"
        }
    }

    private fun markerPayload(source: ByteArray, contentSalt: ByteArray, context: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(MARKER_DOMAIN)
        digest.update(0)
        digest.update(contentSalt)
        digest.update(0)
        digest.update(context.toByteArray(Charsets.UTF_8))
        digest.update(0)
        digest.update(MessageDigest.getInstance("SHA-256").digest(source))
        return MARKER_MAGIC + digest.digest()
    }

    private fun normalizedHead(bytes: ByteArray): ByteArray {
        require(bytes.size >= HEAD_ADJUSTMENT_END) { "SFNT head table is truncated" }
        return bytes.copyOf().also { normalized ->
            (HEAD_ADJUSTMENT_OFFSET until HEAD_ADJUSTMENT_END).forEach { normalized[it] = 0 }
        }
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

    private fun readUInt16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun readUInt32(bytes: ByteArray, offset: Int): Long =
        ((bytes[offset].toLong() and 0xffL) shl 24) or
            ((bytes[offset + 1].toLong() and 0xffL) shl 16) or
            ((bytes[offset + 2].toLong() and 0xffL) shl 8) or
            (bytes[offset + 3].toLong() and 0xffL)

    private fun checkedInt(value: Long, label: String): Int {
        require(value <= Int.MAX_VALUE) { "$label exceeds the supported size" }
        return value.toInt()
    }

    private fun searchRange(tableCount: Int): Int = Integer.highestOneBit(tableCount) * TABLE_RECORD_BYTES

    private fun entrySelector(tableCount: Int): Int = Integer.numberOfTrailingZeros(Integer.highestOneBit(tableCount))

    private fun align4(value: Int): Int = (value + 3) and -4

    private fun tagName(tag: Int): String = byteArrayOf(
        (tag ushr 24).toByte(),
        (tag ushr 16).toByte(),
        (tag ushr 8).toByte(),
        tag.toByte(),
    ).toString(Charsets.ISO_8859_1)

    private data class SfntFont(val scalerType: Int, val tables: List<SfntTable>)

    private data class SfntTable(val tag: Int, val bytes: ByteArray, val offset: Int = 0)

    private companion object {
        const val OFFSET_TABLE_BYTES = 12
        const val TABLE_RECORD_BYTES = 16
        const val MAX_TABLE_COUNT = 4095
        const val HEAD_ADJUSTMENT_OFFSET = 8
        const val HEAD_ADJUSTMENT_END = 12
        const val HEAD_TAG = 0x68656164
        const val DSIG_TAG = 0x44534947
        const val DSIG_HEADER_BYTES = 8
        const val DSIG_SIGNATURE_COUNT_OFFSET = 4
        const val MARKER_TAG = 0x536c6e6b
        const val FONT_CHECKSUM_MAGIC = 0xb1b0afbaL
        const val UINT32_MASK = 0xffffffffL
        val SUPPORTED_SCALER_TYPES = setOf(0x00010000, 0x4f54544f, 0x74727565, 0x74797031)
        val MARKER_MAGIC = "HA13".toByteArray(Charsets.US_ASCII)
        val MARKER_DOMAIN = "com.holin.android.hardening/1.3.0/sfnt/v1".toByteArray(Charsets.US_ASCII)
    }
}
