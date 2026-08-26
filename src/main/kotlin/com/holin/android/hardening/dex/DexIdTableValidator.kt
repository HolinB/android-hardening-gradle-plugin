package com.holin.android.hardening.dex

/** Validates DEX ID-table invariants that dexlib2 accepts but ART enforces strictly. */
object DexIdTableValidator {
    fun requireValid(bytes: ByteArray, label: String) {
        require(bytes.size >= DEX_HEADER_SIZE) {
            "$label DEX header is truncated: ${bytes.size} bytes"
        }

        val methodIdsSize = readUnsignedInt(bytes, METHOD_IDS_SIZE_OFFSET)
        val methodIdsOffset = readUnsignedInt(bytes, METHOD_IDS_OFFSET_OFFSET)
        if (methodIdsSize == 0L) return

        val methodIdsBytes = methodIdsSize * METHOD_ID_ITEM_SIZE
        val methodIdsEnd = methodIdsOffset + methodIdsBytes
        require(
            methodIdsOffset >= DEX_HEADER_SIZE &&
                methodIdsEnd >= methodIdsOffset &&
                methodIdsEnd <= bytes.size.toLong(),
        ) {
            "$label method_ids section is out of bounds: " +
                "offset=$methodIdsOffset size=$methodIdsSize fileSize=${bytes.size}"
        }

        var previous = readMethodId(bytes, methodIdsOffset.toInt())
        var index = 1L
        while (index < methodIdsSize) {
            val currentOffset = methodIdsOffset + index * METHOD_ID_ITEM_SIZE
            val current = readMethodId(bytes, currentOffset.toInt())
            val ordering = previous.compareTo(current)
            require(ordering < 0) {
                val kind = if (ordering == 0) "duplicate" else "out-of-order"
                "$label $kind method_id at indices ${index - 1} and $index: " +
                    "previous=$previous current=$current"
            }
            previous = current
            index++
        }
    }

    private fun readMethodId(bytes: ByteArray, offset: Int): MethodIdKey = MethodIdKey(
        classIndex = readUnsignedShort(bytes, offset),
        protoIndex = readUnsignedShort(bytes, offset + Short.SIZE_BYTES),
        nameIndex = readUnsignedInt(bytes, offset + 2 * Short.SIZE_BYTES),
    )

    private fun readUnsignedShort(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
            ((bytes[offset + 1].toInt() and 0xff) shl Byte.SIZE_BITS)

    private fun readUnsignedInt(bytes: ByteArray, offset: Int): Long =
        (bytes[offset].toLong() and 0xffL) or
            ((bytes[offset + 1].toLong() and 0xffL) shl 8) or
            ((bytes[offset + 2].toLong() and 0xffL) shl 16) or
            ((bytes[offset + 3].toLong() and 0xffL) shl 24)

    private data class MethodIdKey(
        val classIndex: Int,
        val nameIndex: Long,
        val protoIndex: Int,
    ) : Comparable<MethodIdKey> {
        override fun compareTo(other: MethodIdKey): Int =
            compareValuesBy(this, other, MethodIdKey::classIndex, MethodIdKey::nameIndex, MethodIdKey::protoIndex)

        override fun toString(): String =
            "[class_idx=$classIndex, name_idx=$nameIndex, proto_idx=$protoIndex]"
    }

    private const val DEX_HEADER_SIZE = 0x70L
    private const val METHOD_IDS_SIZE_OFFSET = 0x58
    private const val METHOD_IDS_OFFSET_OFFSET = 0x5c
    private const val METHOD_ID_ITEM_SIZE = 8L
}
