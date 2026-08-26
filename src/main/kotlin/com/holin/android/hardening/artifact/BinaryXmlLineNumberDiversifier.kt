package com.holin.android.hardening.artifact

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

data class BinaryXmlLineNumberVerification(
    val changedNodeCount: Int,
)

class BinaryXmlLineNumberDiversifier {
    fun diversify(
        original: ByteArray,
        contentSaltSha256: String,
        apkPath: String,
    ): ByteArray {
        require(SHA_256.matches(contentSaltSha256)) { "binary XML content salt must be a lowercase SHA-256" }
        requireApkXmlPath(apkPath)
        val parsed = BinaryXmlParser.parse(original)
        val diversified = original.copyOf()
        parsed.nodes.forEachIndexed { ordinal, node ->
            val originalLine = readInt(original, node.lineNumberOffset)
            var probe = 0
            var replacement: Int
            do {
                replacement = replacementLineNumber(
                    contentSaltSha256 = contentSaltSha256,
                    apkPath = apkPath,
                    ordinal = ordinal,
                    type = node.chunk.type,
                    original = original,
                    probe = probe++,
                )
            } while (replacement == originalLine)
            writeInt(diversified, node.lineNumberOffset, replacement)
        }
        BinaryXmlLineNumberDiversificationVerifier().verify(original, diversified)
        return diversified
    }

    private fun replacementLineNumber(
        contentSaltSha256: String,
        apkPath: String,
        ordinal: Int,
        type: Int,
        original: ByteArray,
        probe: Int,
    ): Int {
        val digest = MessageDigest.getInstance("SHA-256").apply {
            updateFramed(DOMAIN.toByteArray(StandardCharsets.UTF_8))
            updateFramed(contentSaltSha256.toByteArray(StandardCharsets.US_ASCII))
            updateFramed(apkPath.toByteArray(StandardCharsets.UTF_8))
            updateFramed(intBytes(ordinal))
            updateFramed(intBytes(type))
            updateFramed(original)
            updateFramed(intBytes(probe))
        }.digest()
        return (ByteBuffer.wrap(digest).int and Int.MAX_VALUE).coerceAtLeast(1)
    }

    private fun MessageDigest.updateFramed(value: ByteArray) {
        update(intBytes(value.size))
        update(value)
    }

    private fun intBytes(value: Int): ByteArray = ByteBuffer.allocate(Int.SIZE_BYTES).putInt(value).array()

    private companion object {
        const val DOMAIN = "com.holin.android.hardening/1.2.0/apk-binary-xml-line-number/v1"
        val SHA_256 = Regex("[0-9a-f]{64}")
    }
}

class BinaryXmlLineNumberDiversificationVerifier {
    fun verify(original: ByteArray, candidate: ByteArray): BinaryXmlLineNumberVerification {
        require(original.size == candidate.size) { "binary XML candidate length differs from the original" }
        val originalParsed = BinaryXmlParser.parse(original)
        val candidateParsed = BinaryXmlParser.parse(candidate)
        require(originalParsed.chunks == candidateParsed.chunks) {
            "binary XML candidate chunk topology differs from the original"
        }
        val originalOffsets = originalParsed.nodes.map(BinaryXmlNode::lineNumberOffset)
        val candidateOffsets = candidateParsed.nodes.map(BinaryXmlNode::lineNumberOffset)
        require(originalOffsets == candidateOffsets) {
            "binary XML candidate line-number offsets differ from the original"
        }
        val allowedOffsets = originalOffsets.flatMapTo(linkedSetOf()) { offset -> offset until offset + Int.SIZE_BYTES }
        val changedOffsets = original.indices.filterTo(linkedSetOf()) { index -> original[index] != candidate[index] }
        require(changedOffsets.isNotEmpty()) { "binary XML candidate is unchanged" }
        require(changedOffsets.all(allowedOffsets::contains)) {
            "binary XML candidate changed bytes outside node line numbers"
        }
        originalOffsets.forEach { offset ->
            val candidateLine = readInt(candidate, offset)
            require(candidateLine > 0) { "binary XML candidate contains a non-positive node line number" }
            require(readInt(original, offset) != candidateLine) {
                "binary XML candidate left a node line number unchanged"
            }
        }
        val restored = candidate.copyOf()
        originalOffsets.forEach { offset ->
            original.copyInto(restored, destinationOffset = offset, startIndex = offset, endIndex = offset + Int.SIZE_BYTES)
        }
        require(restored.contentEquals(original)) {
            "binary XML candidate does not normalize byte-for-byte to the original"
        }
        return BinaryXmlLineNumberVerification(originalOffsets.size)
    }
}

private object BinaryXmlParser {
    fun parse(bytes: ByteArray): BinaryXmlDocument {
        require(bytes.size >= CHUNK_HEADER_SIZE) { "binary XML is truncated before its root header" }
        val root = chunkAt(bytes, 0)
        require(root.type == RES_XML_TYPE) { "binary XML has an unsupported root chunk type" }
        require(root.headerSize == CHUNK_HEADER_SIZE) { "binary XML has an unsupported root header size" }
        require(root.size == bytes.size) { "binary XML root size does not exactly match its bytes" }

        val chunks = mutableListOf<BinaryXmlChunk>()
        val nodes = mutableListOf<BinaryXmlNode>()
        var offset = root.headerSize
        var previousEnd = offset
        while (offset < root.size) {
            val chunk = chunkAt(bytes, offset)
            require(chunk.type in SUPPORTED_CHILD_TYPES) { "binary XML contains an unsupported child chunk type" }
            require(offset >= previousEnd) { "binary XML child chunks overlap" }
            require(chunks.none { it.offset == chunk.offset }) { "binary XML contains a duplicate child chunk" }
            chunks += chunk
            when (chunk.type) {
                RES_STRING_POOL_TYPE -> validateStringPool(bytes, chunk)
                RES_XML_RESOURCE_MAP_TYPE -> {
                    require(chunk.headerSize == CHUNK_HEADER_SIZE &&
                        (chunk.size - chunk.headerSize) % Int.SIZE_BYTES == 0
                    ) { "binary XML resource map has an unsupported shape" }
                }
                in RES_XML_NODE_TYPES -> {
                    validateNode(bytes, chunk)
                    nodes += BinaryXmlNode(chunk, offset + CHUNK_HEADER_SIZE)
                }
            }
            previousEnd = Math.addExact(offset, chunk.size)
            offset = previousEnd
        }
        require(offset == root.size) { "binary XML child chunks do not exactly fill the root" }
        require(chunks.count { it.type == RES_STRING_POOL_TYPE } == 1 && chunks.first().type == RES_STRING_POOL_TYPE) {
            "binary XML must contain exactly one leading string pool"
        }
        require(chunks.count { it.type == RES_XML_RESOURCE_MAP_TYPE } <= 1) {
            "binary XML contains a duplicate resource map"
        }
        require(chunks.indexOfFirst { it.type == RES_XML_RESOURCE_MAP_TYPE } in listOf(-1, 1)) {
            "binary XML resource map must immediately follow the string pool"
        }
        require(nodes.isNotEmpty()) { "binary XML contains no tree nodes" }
        return BinaryXmlDocument(root, chunks, nodes)
    }

    private fun validateStringPool(bytes: ByteArray, chunk: BinaryXmlChunk) {
        require(chunk.headerSize == STRING_POOL_HEADER_SIZE) {
            "binary XML string pool has an unsupported header size"
        }
        val stringCount = readUnsignedInt(bytes, chunk.offset + 8)
        val styleCount = readUnsignedInt(bytes, chunk.offset + 12)
        val flags = readUnsignedInt(bytes, chunk.offset + 16)
        val stringsStart = readUnsignedInt(bytes, chunk.offset + 20)
        val stylesStart = readUnsignedInt(bytes, chunk.offset + 24)
        require(stringCount in 1..Int.MAX_VALUE.toLong()) {
            "binary XML string pool must contain at least one string"
        }
        require(styleCount == 0L) { "binary XML string pools with styles are unsupported" }
        require(flags and STRING_POOL_ALLOWED_FLAGS.inv().toLong() == 0L) {
            "binary XML string pool contains unsupported flags"
        }
        val offsetsEnd = STRING_POOL_HEADER_SIZE.toLong() +
            (stringCount + styleCount) * Int.SIZE_BYTES
        require(offsetsEnd <= chunk.size.toLong()) {
            "binary XML string pool offset arrays exceed the chunk"
        }
        require(stringsStart >= offsetsEnd && stringsStart < chunk.size && stringsStart % 4L == 0L) {
            "binary XML string pool string-data offset is invalid"
        }
        require(stylesStart == 0L) { "binary XML string pool has style data without styles" }
        val stringsEnd = chunk.size.toLong()
        val stringDataSize = stringsEnd - stringsStart
        val utf8 = flags and STRING_POOL_UTF8_FLAG.toLong() != 0L
        repeat(stringCount.toInt()) { index ->
            val relativeOffset = readUnsignedInt(
                bytes,
                chunk.offset + STRING_POOL_HEADER_SIZE + index * Int.SIZE_BYTES,
            )
            require(relativeOffset < stringDataSize) { "binary XML string pool string offset is invalid" }
            validateString(
                bytes = bytes,
                offset = chunk.offset + stringsStart.toInt() + relativeOffset.toInt(),
                end = chunk.offset + stringsEnd.toInt(),
                utf8 = utf8,
            )
        }
    }

    private fun validateString(bytes: ByteArray, offset: Int, end: Int, utf8: Boolean) {
        if (utf8) {
            val (utf16Length, byteLengthOffset) = readLength8(bytes, offset, end)
            val (byteLength, dataOffset) = readLength8(bytes, byteLengthOffset, end)
            val dataEnd = dataOffset.toLong() + byteLength
            require(dataEnd < end && bytes[dataEnd.toInt()] == 0.toByte()) {
                "binary XML string pool contains a truncated UTF-8 string"
            }
            val decodedUtf16Length = modifiedUtf8Utf16Length(bytes, dataOffset, byteLength)
            require(decodedUtf16Length == utf16Length) {
                "binary XML string pool UTF-8 length fields are inconsistent"
            }
        } else {
            val (utf16Length, dataOffset) = readLength16(bytes, offset, end)
            val dataEnd = dataOffset.toLong() + utf16Length.toLong() * 2L
            require(dataEnd + 2L <= end && readUnsignedShort(bytes, dataEnd.toInt()) == 0) {
                "binary XML string pool contains a truncated UTF-16 string"
            }
            val decoded = decodeString(bytes, dataOffset, (utf16Length.toLong() * 2L).toInt(), StandardCharsets.UTF_16LE)
            require(decoded.length == utf16Length) {
                "binary XML string pool UTF-16 length field is inconsistent"
            }
        }
    }

    private fun modifiedUtf8Utf16Length(bytes: ByteArray, offset: Int, length: Int): Int {
        val endLong = offset.toLong() + length
        requireModifiedUtf8(offset >= 0 && length >= 0 && endLong <= bytes.size.toLong())
        val end = endLong.toInt()
        var cursor = offset
        var utf16Length = 0
        while (cursor < end) {
            val first = bytes[cursor].toInt() and 0xff
            when {
                first <= 0x7f -> cursor++
                first in 0xc2..0xdf -> {
                    requireModifiedUtf8(isContinuation(bytes, cursor + 1, end))
                    cursor += 2
                }
                first == 0xe0 -> {
                    requireModifiedUtf8(
                        cursor + 2 < end &&
                            (bytes[cursor + 1].toInt() and 0xff) in 0xa0..0xbf &&
                            isContinuation(bytes, cursor + 2, end),
                    )
                    cursor += 3
                }
                first in 0xe1..0xec || first in 0xee..0xef -> {
                    requireModifiedUtf8(
                        isContinuation(bytes, cursor + 1, end) &&
                            isContinuation(bytes, cursor + 2, end),
                    )
                    cursor += 3
                }
                first == 0xed -> {
                    requireModifiedUtf8(cursor + 2 < end && isContinuation(bytes, cursor + 2, end))
                    val second = bytes[cursor + 1].toInt() and 0xff
                    when (second) {
                        in 0x80..0x9f -> cursor += 3
                        in 0xa0..0xaf -> {
                            // AAPT encodes a supplementary code point as a paired CESU-8 surrogate.
                            requireModifiedUtf8(
                                cursor + 5 < end &&
                                    (bytes[cursor + 3].toInt() and 0xff) == 0xed &&
                                    (bytes[cursor + 4].toInt() and 0xff) in 0xb0..0xbf &&
                                    isContinuation(bytes, cursor + 5, end),
                            )
                            cursor += 6
                            utf16Length++
                        }
                        else -> malformedStringData()
                    }
                }
                else -> malformedStringData()
            }
            utf16Length++
        }
        return utf16Length
    }

    private fun isContinuation(bytes: ByteArray, offset: Int, end: Int): Boolean =
        offset < end && bytes[offset].toInt() and 0xc0 == 0x80

    private fun requireModifiedUtf8(condition: Boolean) {
        if (!condition) malformedStringData()
    }

    private fun malformedStringData(): Nothing =
        throw IllegalArgumentException("binary XML string pool contains malformed string data")

    private fun readLength8(bytes: ByteArray, offset: Int, end: Int): Pair<Int, Int> {
        require(offset < end) { "binary XML string pool length is truncated" }
        val first = bytes[offset].toInt() and 0xff
        return if (first and 0x80 == 0) {
            first to offset + 1
        } else {
            require(offset + 1 < end) { "binary XML string pool length is truncated" }
            (((first and 0x7f) shl 8) or (bytes[offset + 1].toInt() and 0xff)) to offset + 2
        }
    }

    private fun readLength16(bytes: ByteArray, offset: Int, end: Int): Pair<Int, Int> {
        require(offset <= end - 2) { "binary XML string pool length is truncated" }
        val first = readUnsignedShort(bytes, offset)
        return if (first and 0x8000 == 0) {
            first to offset + 2
        } else {
            require(offset <= end - 4) { "binary XML string pool length is truncated" }
            (((first and 0x7fff) shl 16) or readUnsignedShort(bytes, offset + 2)) to offset + 4
        }
    }

    private fun decodeString(
        bytes: ByteArray,
        offset: Int,
        length: Int,
        charset: java.nio.charset.Charset,
    ): String = try {
        charset.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes, offset, length))
            .toString()
    } catch (_: Exception) {
        throw IllegalArgumentException("binary XML string pool contains malformed string data")
    }

    private fun validateNode(bytes: ByteArray, chunk: BinaryXmlChunk) {
        require(chunk.headerSize == NODE_HEADER_SIZE) {
            "binary XML node has an unsupported header size"
        }
        val expectedFixedSize = when (chunk.type) {
            RES_XML_START_NAMESPACE_TYPE,
            RES_XML_END_NAMESPACE_TYPE,
            RES_XML_END_ELEMENT_TYPE,
            -> NODE_HEADER_SIZE + NAMESPACE_OR_END_ELEMENT_PAYLOAD_SIZE
            RES_XML_CDATA_TYPE -> NODE_HEADER_SIZE + CDATA_PAYLOAD_SIZE
            RES_XML_START_ELEMENT_TYPE -> null
            else -> error("unsupported binary XML node type")
        }
        if (expectedFixedSize != null) {
            require(chunk.size == expectedFixedSize) { "binary XML node has an unsupported payload shape" }
            if (chunk.type == RES_XML_CDATA_TYPE) {
                validateCdataTypedValue(bytes, chunk.offset + NODE_HEADER_SIZE + Int.SIZE_BYTES)
            }
            return
        }

        require(chunk.size >= NODE_HEADER_SIZE + START_ELEMENT_PAYLOAD_SIZE) {
            "binary XML start-element payload is truncated"
        }
        val attributeStart = readUnsignedShort(bytes, chunk.offset + 24)
        val attributeSize = readUnsignedShort(bytes, chunk.offset + 26)
        val attributeCount = readUnsignedShort(bytes, chunk.offset + 28)
        require(attributeStart == START_ELEMENT_PAYLOAD_SIZE && attributeSize == ATTRIBUTE_SIZE) {
            "binary XML start-element attribute layout is unsupported"
        }
        val attributesEnd = NODE_HEADER_SIZE.toLong() + attributeStart +
            attributeCount.toLong() * attributeSize
        require(attributesEnd == chunk.size.toLong()) {
            "binary XML start-element attribute payload is inconsistent"
        }
        listOf(30, 32, 34).forEach { relativeOffset ->
            require(readUnsignedShort(bytes, chunk.offset + relativeOffset) <= attributeCount) {
                "binary XML start-element special attribute index is invalid"
            }
        }
        repeat(attributeCount) { index ->
            val attributeOffset = chunk.offset + NODE_HEADER_SIZE + attributeStart + index * attributeSize
            validateTypedValue(bytes, attributeOffset + 12)
        }
    }

    private fun validateCdataTypedValue(bytes: ByteArray, offset: Int) {
        if (readUnsignedShort(bytes, offset) == 0) {
            require((offset until offset + TYPED_VALUE_SIZE).all { index -> bytes[index] == 0.toByte() }) {
                "binary XML absent CDATA typed value must be zeroed"
            }
        } else {
            validateTypedValue(bytes, offset)
        }
    }

    private fun validateTypedValue(bytes: ByteArray, offset: Int) {
        require(readUnsignedShort(bytes, offset) == TYPED_VALUE_SIZE) {
            "binary XML typed value has an unsupported size"
        }
        require(bytes[offset + 2] == 0.toByte()) { "binary XML typed value reserved byte must be zero" }
    }

    private fun chunkAt(bytes: ByteArray, offset: Int): BinaryXmlChunk {
        require(offset >= 0 && offset <= bytes.size - CHUNK_HEADER_SIZE) { "binary XML chunk header is truncated" }
        val type = readUnsignedShort(bytes, offset)
        val headerSize = readUnsignedShort(bytes, offset + 2)
        val sizeLong = readUnsignedInt(bytes, offset + 4)
        require(headerSize >= CHUNK_HEADER_SIZE) { "binary XML chunk header size is too small" }
        require(sizeLong >= headerSize.toLong()) { "binary XML chunk size is smaller than its header" }
        require(sizeLong <= Int.MAX_VALUE.toLong()) { "binary XML chunk size is unsupported" }
        val size = sizeLong.toInt()
        val end = try {
            Math.addExact(offset, size)
        } catch (_: ArithmeticException) {
            throw IllegalArgumentException("binary XML chunk bounds overflow")
        }
        require(end <= bytes.size) { "binary XML chunk extends beyond its bytes" }
        return BinaryXmlChunk(offset, type, headerSize, size)
    }

    private const val CHUNK_HEADER_SIZE = 8
    private const val STRING_POOL_HEADER_SIZE = 28
    private const val STRING_POOL_SORTED_FLAG = 0x00000001
    private const val STRING_POOL_UTF8_FLAG = 0x00000100
    private const val STRING_POOL_ALLOWED_FLAGS = STRING_POOL_SORTED_FLAG or STRING_POOL_UTF8_FLAG
    private const val NODE_HEADER_SIZE = 16
    private const val NAMESPACE_OR_END_ELEMENT_PAYLOAD_SIZE = 8
    private const val START_ELEMENT_PAYLOAD_SIZE = 20
    private const val ATTRIBUTE_SIZE = 20
    private const val TYPED_VALUE_SIZE = 8
    private const val CDATA_PAYLOAD_SIZE = 12
    private const val RES_XML_TYPE = 0x0003
    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_RESOURCE_MAP_TYPE = 0x0180
    private const val RES_XML_START_NAMESPACE_TYPE = 0x0100
    private const val RES_XML_END_NAMESPACE_TYPE = 0x0101
    private const val RES_XML_START_ELEMENT_TYPE = 0x0102
    private const val RES_XML_END_ELEMENT_TYPE = 0x0103
    private const val RES_XML_CDATA_TYPE = 0x0104
    private val RES_XML_NODE_TYPES = 0x0100..0x0104
    private val SUPPORTED_CHILD_TYPES = setOf(RES_STRING_POOL_TYPE, RES_XML_RESOURCE_MAP_TYPE) + RES_XML_NODE_TYPES
}

private data class BinaryXmlDocument(
    val root: BinaryXmlChunk,
    val chunks: List<BinaryXmlChunk>,
    val nodes: List<BinaryXmlNode>,
)

private data class BinaryXmlChunk(
    val offset: Int,
    val type: Int,
    val headerSize: Int,
    val size: Int,
)

private data class BinaryXmlNode(
    val chunk: BinaryXmlChunk,
    val lineNumberOffset: Int,
)

private fun requireApkXmlPath(path: String) {
    BundleZipRewriter.requireSafeUniqueEntryNames(listOf(path))
    require(APK_XML_PATH.matches(path)) { "binary XML APK path must be an exact res/**/*.xml path" }
}

private fun readUnsignedShort(bytes: ByteArray, offset: Int): Int =
    (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

private fun readUnsignedInt(bytes: ByteArray, offset: Int): Long = readInt(bytes, offset).toLong() and 0xffff_ffffL

private fun readInt(bytes: ByteArray, offset: Int): Int =
    (bytes[offset].toInt() and 0xff) or
        ((bytes[offset + 1].toInt() and 0xff) shl 8) or
        ((bytes[offset + 2].toInt() and 0xff) shl 16) or
        ((bytes[offset + 3].toInt() and 0xff) shl 24)

private fun writeInt(bytes: ByteArray, offset: Int, value: Int) {
    bytes[offset] = value.toByte()
    bytes[offset + 1] = (value ushr 8).toByte()
    bytes[offset + 2] = (value ushr 16).toByte()
    bytes[offset + 3] = (value ushr 24).toByte()
}

private val APK_XML_PATH = Regex("res/(?:[^/]+/)+[^/]+\\.xml")
